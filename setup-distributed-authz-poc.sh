#!/usr/bin/env bash
set -e

mkdir -p distributed-authz-poc/ory/keto
mkdir -p distributed-authz-poc/ory/oathkeeper
mkdir -p distributed-authz-poc/services/mock-oidc
mkdir -p distributed-authz-poc/services/mock-odb
mkdir -p distributed-authz-poc/services/governance
mkdir -p distributed-authz-poc/services/app-foo
mkdir -p distributed-authz-poc/services/api-bar

cd distributed-authz-poc

# ------------------------------------------------------------------------------
# 1. docker-compose.yml
# ------------------------------------------------------------------------------
cat << 'EOF' > docker-compose.yml
services:
  mock-oidc:
    image: node:20-alpine
    working_dir: /app
    volumes:
      - ./services/mock-oidc:/app
    command: node server.js
    ports:
      - "4000:4000"

  mock-odb:
    image: node:20-alpine
    working_dir: /app
    volumes:
      - ./services/mock-odb:/app
    command: node server.js
    ports:
      - "4001:4001"

  governance:
    image: node:20-alpine
    working_dir: /app
    volumes:
      - ./services/governance:/app
    environment:
      - ODB_URL=http://mock-odb:4001
      - KETO_WRITE_URL=http://keto:4467
    command: node server.js
    ports:
      - "4002:4002"
    depends_on:
      - mock-odb
      - keto

  keto-migrate:
    image: oryd/keto:v0.13.0-alpha.0
    volumes:
      - ./ory/keto:/etc/config/keto
      - keto-data:/var/lib/sqlite
    command: migrate up -y --config /etc/config/keto/keto.yml

  keto:
    image: oryd/keto:v0.13.0-alpha.0
    volumes:
      - ./ory/keto:/etc/config/keto
      - keto-data:/var/lib/sqlite
    command: serve --config /etc/config/keto/keto.yml
    ports:
      - "4466:4466"
      - "4467:4467"
    depends_on:
      - keto-migrate

  oathkeeper:
    image: oryd/oathkeeper:v0.40.8
    volumes:
      - ./ory/oathkeeper:/etc/config/oathkeeper
    command: serve --config /etc/config/oathkeeper/oathkeeper.yml
    ports:
      - "4455:4455"
    depends_on:
      - mock-oidc
      - keto

  app-foo:
    image: node:20-alpine
    working_dir: /app
    volumes:
      - ./services/app-foo:/app
    environment:
      - OIDC_URL=http://mock-oidc:4000
      - ODB_URL=http://mock-odb:4001
      - GATEWAY_URL=http://oathkeeper:4455
    command: node server.js
    ports:
      - "4003:4003"

  api-bar:
    image: node:20-alpine
    working_dir: /app
    volumes:
      - ./services/api-bar:/app
    command: node server.js
    ports:
      - "4004:4004"

volumes:
  keto-data:
EOF

# ------------------------------------------------------------------------------
# 2. Ory Keto Config & Generic OPL Schema
# ------------------------------------------------------------------------------
cat << 'EOF' > ory/keto/keto.yml
version: v0.13.0-alpha.0
dsn: sqlite:///var/lib/sqlite/keto.db?_fk=true&mode=rwc

serve:
  read:
    host: 0.0.0.0
    port: 4466
  write:
    host: 0.0.0.0
    port: 4467

namespaces:
  location: file:///etc/config/keto/namespaces.ts
EOF

cat << 'EOF' > ory/keto/namespaces.ts
import { Namespace, Context } from "@ory/keto-namespace-types"

class User implements Namespace {}

class Team implements Namespace {
  related: {
    members: User[]
  }
}

class Resource implements Namespace {
  related: {
    parent: Resource[]
    secret_admins: (User | Team)[]
    users: (User | Team)[]
  }

  permits = {
    view_secrets: (ctx: Context): boolean =>
      this.related.secret_admins.includes(ctx.subject) ||
      this.related.secret_admins.traverse((t) => t.related.members.includes(ctx.subject)) ||
      this.related.parent.traverse((p) => p.permits.view_secrets(ctx)),

    access: (ctx: Context): boolean =>
      this.related.users.includes(ctx.subject) ||
      this.related.users.traverse((t) => t.related.members.includes(ctx.subject)) ||
      this.related.parent.traverse((p) => p.permits.access(ctx)),
  }
}
EOF

# ------------------------------------------------------------------------------
# 3. Ory Oathkeeper Config & Access Rules
# ------------------------------------------------------------------------------
cat << 'EOF' > ory/oathkeeper/oathkeeper.yml
serve:
  proxy:
    host: 0.0.0.0
    port: 4455

access_rules:
  repositories:
    - file:///etc/config/oathkeeper/access-rules.yaml

authenticators:
  jwt:
    enabled: true
    config:
      jwks_urls:
        - http://mock-oidc:4000/.well-known/jwks.json

authorizers:
  allow:
    enabled: true
  remote_json:
    enabled: true
    config:
      remote: http://keto:4466/relation-tuples/check
      forward_response_headers_to_upstream: []

mutators:
  header:
    enabled: true
  noop:
    enabled: true

errors:
  fallback:
    - json
EOF

cat << 'EOF' > ory/oathkeeper/access-rules.yaml
- id: foo-view-secrets
  upstream:
    url: http://app-foo:4003
  match:
    url: http://oathkeeper:4455/foo/secrets/<[a-zA-Z0-9_-]+>
    methods:
      - GET
  authenticators:
    - handler: jwt
  authorizer:
    handler: remote_json
    config:
      remote: http://keto:4466/relation-tuples/check
      payload: |
        {
          "namespace": "Resource",
          "object": "app:{{ index .MatchContext.RegexpCaptureGroups 0 }}",
          "relation": "view_secrets",
          "subject_id": "{{ print .Subject }}"
        }
  mutators:
    - handler: header
      config:
        headers:
          X-User-ID: "{{ print .Subject }}"

- id: policy-foo-to-bar-all-apis
  upstream:
    url: http://api-bar:4004
  match:
    url: http://oathkeeper:4455/bar/<**>
    methods:
      - GET
      - POST
      - PUT
      - DELETE
  authenticators:
    - handler: jwt
      config:
        required_scope:
          - bar:all
        token_from:
          header: Authorization
  authorizer:
    handler: allow
  mutators:
    - handler: header
      config:
        headers:
          X-Caller-App: "{{ print .Extra.azp }}"
          X-Acting-User: "{{ print .Subject }}"
EOF

# ------------------------------------------------------------------------------
# 4. Mock OIDC Provider (CommonJS)
# ------------------------------------------------------------------------------
cat << 'EOF' > services/mock-oidc/server.js
const http = require("http");
const crypto = require("crypto");

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

const jwk = publicKey.export({ format: "jwk" });
jwk.kid = "mock-key-1";
jwk.alg = "RS256";
jwk.use = "sig";

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signJwt(payload) {
  const header = { alg: "RS256", typ: "JWT", kid: "mock-key-1" };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    iss: "http://mock-oidc:4000",
    iat: now,
    exp: now + 3600,
    ...payload,
  };
  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(
    JSON.stringify(fullPayload)
  )}`;
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(unsigned);
  const signature = sign
    .sign(privateKey)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `${unsigned}.${signature}`;
}

const server = http.createServer((req, res) => {
  if (req.url === "/.well-known/jwks.json") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ keys: [jwk] }));
  }

  if (req.url === "/token" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const data = JSON.parse(body || "{}");
      const token = signJwt({
        sub: data.sub || "alice",
        azp: data.azp || "app-foo",
        scope: data.scope || "openid profile",
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: token, token_type: "Bearer" }));
    });
    return;
  }

  res.writeHead(404);
  res.end();
});

server.listen(4000, () => console.log("Mock OIDC running on :4000"));
EOF

# ------------------------------------------------------------------------------
# 5. Mock ODB (CommonJS + Platform-Neutral YAML Reference)
# ------------------------------------------------------------------------------
cat << 'EOF' > services/mock-odb/data.yaml
jiras:
  - jiraId: JIRA-100
    name: Core Payments Platform

applications:
  - resourceId: app-foo
    label: Foo User Portal
    stackId: stack-frontend-01
    jiraId: JIRA-100
    secrets:
      STRIPE_KEY: sk_live_foo_998877
      DB_PASS: super_secret_foo_pass

  - resourceId: app-bar
    label: Bar Core API
    stackId: stack-backend-01
    jiraId: JIRA-100
    secrets:
      INTERNAL_SIGNING_KEY: bar_key_112233
EOF

cat << 'EOF' > services/mock-odb/server.js
const http = require("http");

const odb = {
  jiras: [{ jiraId: "JIRA-100", name: "Core Payments Platform" }],
  applications: [
    {
      resourceId: "app-foo",
      label: "Foo User Portal",
      stackId: "stack-frontend-01",
      jiraId: "JIRA-100",
      secrets: {
        STRIPE_KEY: "sk_live_foo_998877",
        DB_PASS: "super_secret_foo_pass",
      },
    },
    {
      resourceId: "app-bar",
      label: "Bar Core API",
      stackId: "stack-backend-01",
      jiraId: "JIRA-100",
      secrets: {
        INTERNAL_SIGNING_KEY: "bar_key_112233",
      },
    },
  ],
};

const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json");

  if (req.url === "/odb" && req.method === "GET") {
    return res.end(JSON.stringify(odb, null, 2));
  }

  if (req.url.startsWith("/odb/applications/") && req.method === "GET") {
    const id = req.url.split("/")[3];
    const app = odb.applications.find((a) => a.resourceId === id);
    if (!app) {
      res.writeHead(404);
      return res.end(JSON.stringify({ error: "Application not found" }));
    }
    return res.end(JSON.stringify(app, null, 2));
  }

  if (req.url === "/odb/applications" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const app = JSON.parse(body);
      if (odb.applications.some((a) => a.resourceId === app.resourceId)) {
        res.writeHead(409);
        return res.end(JSON.stringify({ error: "resourceId must be unique" }));
      }
      odb.applications.push(app);
      res.writeHead(201);
      res.end(JSON.stringify(app));
    });
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(4001, () => console.log("Mock ODB running on :4001"));
EOF

# ------------------------------------------------------------------------------
# 6. Governance & Template Store (CommonJS + Platform-Neutral YAML)
# ------------------------------------------------------------------------------
cat << 'EOF' > services/governance/templates.yaml
roleTemplates:
  - templateId: foo-secret
    description: Grants read access to all secrets for assigned Application or Jira
    ketoRelation: secret_admins

policyTemplates:
  - templateId: pbac-foo-to-bar
    description: Policy-based access granting Foo access to all APIs in Bar
    sourceApp: app-foo
    targetApp: app-bar
    grantedScope: bar:all
    allowAllEndpoints: true
EOF

cat << 'EOF' > services/governance/server.js
const http = require("http");

const ODB_URL = process.env.ODB_URL || "http://mock-odb:4001";
const KETO_WRITE_URL = process.env.KETO_WRITE_URL || "http://keto:4467";

const store = {
  roleTemplates: {
    "foo-secret": {
      templateId: "foo-secret",
      description: "Grants access to view all secrets under an Application or Jira",
      ketoRelation: "secret_admins",
    },
  },
  policyTemplates: {
    "pbac-foo-to-bar": {
      templateId: "pbac-foo-to-bar",
      sourceApp: "app-foo",
      targetApp: "app-bar",
      grantedScope: "bar:all",
      allowAllEndpoints: true,
    },
  },
  approvalsAuditLog: [],
};

function httpRequest(url, method, data) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = data ? JSON.stringify(data) : null;
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method,
        headers: payload
          ? {
              "Content-Type": "application/json",
              "Content-Length": Buffer.byteLength(payload),
            }
          : {},
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, body }));
      }
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function syncTopologyToKeto() {
  const res = await httpRequest(`${ODB_URL}/odb`, "GET");
  const odb = JSON.parse(res.body);

  for (const app of odb.applications) {
    if (app.jiraId) {
      await httpRequest(`${KETO_WRITE_URL}/admin/relation-tuples`, "PUT", {
        namespace: "Resource",
        object: `app:${app.resourceId}`,
        relation: "parent",
        subject_set: {
          namespace: "Resource",
          object: `jira:${app.jiraId}`,
        },
      });
    }
  }
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");

  if (req.url === "/audit" && req.method === "GET") {
    return res.end(JSON.stringify(store, null, 2));
  }

  if (req.url === "/sync-odb" && req.method === "POST") {
    await syncTopologyToKeto();
    return res.end(JSON.stringify({ status: "synced ODB topology to Keto" }));
  }

  if (req.url === "/approve-role" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      const { userId, roleTemplateId, targetType, targetId, approvedBy } =
        JSON.parse(body);
      const template = store.roleTemplates[roleTemplateId];
      if (!template) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "Unknown role template" }));
      }

      const auditEntry = {
        approvalId: `appr-${Date.now()}`,
        timestamp: new Date().toISOString(),
        userId,
        roleTemplateId,
        target: `${targetType}:${targetId}`,
        approvedBy,
        status: "REALIZED",
      };
      store.approvalsAuditLog.push(auditEntry);

      await httpRequest(`${KETO_WRITE_URL}/admin/relation-tuples`, "PUT", {
        namespace: "Resource",
        object: `${targetType}:${targetId}`,
        relation: template.ketoRelation,
        subject_id: userId,
      });

      res.writeHead(201);
      res.end(JSON.stringify(auditEntry));
    });
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(4002, () => console.log("Governance Store running on :4002"));
EOF

# ------------------------------------------------------------------------------
# 7. Application Foo (User-Facing SSO + Secrets + Calls Bar)
# ------------------------------------------------------------------------------
cat << 'EOF' > services/app-foo/server.js
const http = require("http");

const OIDC_URL = process.env.OIDC_URL || "http://mock-oidc:4000";
const ODB_URL = process.env.ODB_URL || "http://mock-odb:4001";
const GATEWAY_URL = process.env.GATEWAY_URL || "http://oathkeeper:4455";

function httpRequest(url, method, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = data ? JSON.stringify(data) : null;
    const reqHeaders = { ...headers };
    if (payload) {
      reqHeaders["Content-Type"] = "application/json";
      reqHeaders["Content-Length"] = Buffer.byteLength(payload);
    }
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method,
        headers: reqHeaders,
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, body }));
      }
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");

  // 1. Simulate User SSO Login to Foo
  if (req.url === "/login" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      const { userId } = JSON.parse(body || '{"userId":"alice"}');
      const tokenRes = await httpRequest(`${OIDC_URL}/token`, "POST", {
        sub: userId,
        azp: "app-foo",
        scope: "openid profile",
      });
      res.writeHead(200);
      res.end(tokenRes.body);
    });
    return;
  }

  // 2. View Secrets endpoint (protected upstream by Oathkeeper + Keto 'foo-secret' check)
  if (req.url.startsWith("/foo/secrets/") && req.method === "GET") {
    const appId = req.url.split("/")[3];
    const verifiedUser = req.headers["x-user-id"] || "unknown";
    const appRes = await httpRequest(`${ODB_URL}/odb/applications/${appId}`, "GET");
    if (appRes.status !== 200) {
      res.writeHead(appRes.status);
      return res.end(appRes.body);
    }
    const appData = JSON.parse(appRes.body);
    res.writeHead(200);
    return res.end(
      JSON.stringify({
        requestedBy: verifiedUser,
        application: appData.resourceId,
        jira: appData.jiraId,
        secrets: appData.secrets,
      })
    );
  }

  // 3. App Foo -> Calls Bar APIs using PBAC token ('bar:all')
  if (req.url.startsWith("/proxy-to-bar/") && req.method === "GET") {
    const subPath = req.url.replace("/proxy-to-bar/", "");
    const userId = req.headers["x-user-id"] || "alice";

    // Mint PBAC service token for Foo -> Bar
    const tokenRes = await httpRequest(`${OIDC_URL}/token`, "POST", {
      sub: userId,
      azp: "app-foo",
      scope: "bar:all",
    });
    const { access_token } = JSON.parse(tokenRes.body);

    const barRes = await httpRequest(
      `${GATEWAY_URL}/bar/${subPath}`,
      "GET",
      null,
      { Authorization: `Bearer ${access_token}` }
    );
    res.writeHead(barRes.status);
    return res.end(barRes.body);
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "Route not found in app-foo" }));
});

server.listen(4003, () => console.log("App Foo running on :4003"));
EOF

# ------------------------------------------------------------------------------
# 8. Application Bar (Backend API protected by PBAC for all routes)
# ------------------------------------------------------------------------------
cat << 'EOF' > services/api-bar/server.js
const http = require("http");

const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json");
  const callerApp = req.headers["x-caller-app"] || "direct-unverified";
  const actingUser = req.headers["x-acting-user"] || "unknown";

  if (req.url === "/bar/orders") {
    return res.end(
      JSON.stringify({
        service: "api-bar",
        endpoint: "/bar/orders",
        authorizedCaller: callerApp,
        actingUser,
        orders: [{ id: "ord-1", amount: 250 }],
      })
    );
  }

  if (req.url === "/bar/invoices") {
    return res.end(
      JSON.stringify({
        service: "api-bar",
        endpoint: "/bar/invoices",
        authorizedCaller: callerApp,
        actingUser,
        invoices: [{ id: "inv-99", status: "PAID" }],
      })
    );
  }

  res.end(
    JSON.stringify({
      service: "api-bar",
      endpoint: req.url,
      authorizedCaller: callerApp,
      actingUser,
      message: "All Bar APIs accessible via Foo->Bar PBAC policy",
    })
  );
});

server.listen(4004, () => console.log("API Bar running on :4004"));
EOF

# ------------------------------------------------------------------------------
# 9. End-to-End Verification Script (test-flow.sh)
# ------------------------------------------------------------------------------
cat << 'EOF' > test-flow.sh
#!/usr/bin/env bash
set -e

echo "1. Syncing ODB Jira -> Application topology into Ory Keto..."
curl -s -X POST http://localhost:4002/sync-odb | cat
echo ""

echo "2. Logging in as 'alice' via Foo SSO..."
ALICE_TOKEN=$(curl -s -X POST http://localhost:4003/login -d '{"userId":"alice"}' | node -pe "JSON.parse(fs.readFileSync(0,'utf8')).access_token")

echo "3. Testing secret access BEFORE 'foo-secret' role approval (Expect 403 Forbidden)..."
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n"   -H "Authorization: Bearer $ALICE_TOKEN"   http://localhost:4455/foo/secrets/app-foo

echo "4. Approving 'foo-secret' role template for 'alice' on JIRA-100 in Governance Store..."
curl -s -X POST http://localhost:4002/approve-role   -d '{"userId":"alice","roleTemplateId":"foo-secret","targetType":"jira","targetId":"JIRA-100","approvedBy":"manager-bob"}'
echo ""

echo "5. Testing secret access AFTER approval (Inherits JIRA-100 -> app-foo & app-bar, Expect 200 OK)..."
curl -s -H "Authorization: Bearer $ALICE_TOKEN" http://localhost:4455/foo/secrets/app-foo
echo ""
curl -s -H "Authorization: Bearer $ALICE_TOKEN" http://localhost:4455/foo/secrets/app-bar
echo ""

echo "6. Testing Application Foo -> Bar Policy-Based Access across all Bar APIs..."
curl -s -H "X-User-ID: alice" http://localhost:4003/proxy-to-bar/orders
echo ""
curl -s -H "X-User-ID: alice" http://localhost:4003/proxy-to-bar/invoices
echo ""

echo "7. Checking Governance Audit Log..."
curl -s http://localhost:4002/audit
echo ""
EOF

chmod +x test-flow.sh

echo "Setup complete! Run:"
echo "  cd distributed-authz-poc && docker compose up -d"
echo "  ./test-flow.sh"
