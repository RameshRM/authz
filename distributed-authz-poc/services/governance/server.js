const http = require("http");
const net = require("net");

const ODB_URL = process.env.ODB_URL || "http://mock-odb:4001";
const KETO_WRITE_URL = process.env.KETO_WRITE_URL || "http://keto:4467";
const LDAP_HOST = process.env.LDAP_HOST || "openldap";
const LDAP_PORT = parseInt(process.env.LDAP_PORT || "389", 10);
const LDAP_BASE_DN = process.env.LDAP_BASE_DN || "dc=internal,dc=local";
const LDAP_ADMIN_DN = process.env.LDAP_ADMIN_DN || "cn=admin,dc=internal,dc=local";
const LDAP_ADMIN_PASSWORD = process.env.LDAP_ADMIN_PASSWORD || "admin";

const store = {
  roleTemplates: {
    "foo-secret": {
      templateId: "foo-secret",
      description: "Grants access to view all secrets under an Application or Jira",
      ketoRelation: "secret_admins",
      ldapGroupCn: "foo-secret",
    },
  },
  policyTemplates: {
    "pbac-foo-to-bar": {
      templateId: "pbac-foo-to-bar",
      description: "Policy-based access granting Foo access to all APIs in Bar",
      sourceApp: "app-foo",
      targetApp: "app-bar",
      grantedScope: "bar:all",
      allowAllEndpoints: true,
    },
  },
  accessRequests: [],
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
        path: u.pathname + u.search,
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

// Minimal raw BER LDAP client for Dual-Write (Bind, Add, Modify) without external npm dependencies
function berLen(len) {
  if (len < 128) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function berTlv(tag, buf) {
  return Buffer.concat([Buffer.from([tag]), berLen(buf.length), buf]);
}
function berInt(val) {
  return berTlv(0x02, Buffer.from([val]));
}
function berOctet(str) {
  const b = Buffer.from(str, "utf8");
  return berTlv(0x04, b);
}
function berSeq(buffers) {
  return berTlv(0x30, Buffer.concat(buffers));
}
function berSet(buffers) {
  return berTlv(0x31, Buffer.concat(buffers));
}

function sendLdapOps(ops) {
  return new Promise((resolve) => {
    const client = net.createConnection({ host: LDAP_HOST, port: LDAP_PORT }, () => {
      let msgId = 1;
      const bindReq = berSeq([
        berInt(msgId++),
        berTlv(0x60, Buffer.concat([berInt(3), berOctet(LDAP_ADMIN_DN), berTlv(0x80, Buffer.from(LDAP_ADMIN_PASSWORD, "utf8"))])),
      ]);
      client.write(bindReq);

      for (const op of ops) {
        if (op.type === "add") {
          const attrs = Object.entries(op.attrs).map(([k, vals]) =>
            berSeq([berOctet(k), berSet(vals.map(berOctet))])
          );
          const addReq = berSeq([
            berInt(msgId++),
            berTlv(0x68, Buffer.concat([berOctet(op.dn), berSeq(attrs)])),
          ]);
          client.write(addReq);
        } else if (op.type === "modifyAdd") {
          const change = berSeq([
            berTlv(0x0a, Buffer.from([0x00])), // operation: add (0)
            berSeq([berOctet(op.attr), berSet(op.vals.map(berOctet))]),
          ]);
          const modReq = berSeq([
            berInt(msgId++),
            berTlv(0x66, Buffer.concat([berOctet(op.dn), berSeq([change])])),
          ]);
          client.write(modReq);
        } else if (op.type === "modifyDelete") {
          const change = berSeq([
            berTlv(0x0a, Buffer.from([0x01])), // operation: delete (1)
            berSeq([berOctet(op.attr), berSet(op.vals.map(berOctet))]),
          ]);
          const modReq = berSeq([
            berInt(msgId++),
            berTlv(0x66, Buffer.concat([berOctet(op.dn), berSeq([change])])),
          ]);
          client.write(modReq);
        }
      }
      setTimeout(() => {
        client.end();
        resolve();
      }, 150);
    });
    client.on("error", (err) => {
      console.error("LDAP write warning:", err.message);
      resolve();
    });
  });
}

async function ensureLdapBase() {
  await sendLdapOps([
    { type: "add", dn: `ou=users,${LDAP_BASE_DN}`, attrs: { objectClass: ["organizationalUnit"], ou: ["users"] } },
    { type: "add", dn: `ou=resources,${LDAP_BASE_DN}`, attrs: { objectClass: ["organizationalUnit"], ou: ["resources"] } },
    {
      type: "add",
      dn: `uid=alice,ou=users,${LDAP_BASE_DN}`,
      attrs: { objectClass: ["inetOrgPerson"], cn: ["Alice User"], sn: ["Alice"], uid: ["alice"] },
    },
    {
      type: "add",
      dn: `uid=bob,ou=users,${LDAP_BASE_DN}`,
      attrs: { objectClass: ["inetOrgPerson"], cn: ["Bob User"], sn: ["Bob"], uid: ["bob"] },
    },
  ]);
}

async function syncTopologyDualWrite() {
  await ensureLdapBase();
  const res = await httpRequest(`${ODB_URL}/odb`, "GET");
  const odb = JSON.parse(res.body);

  const ldapOps = [];
  for (const jira of odb.jiras) {
    ldapOps.push({
      type: "add",
      dn: `ou=${jira.jiraId},ou=resources,${LDAP_BASE_DN}`,
      attrs: { objectClass: ["organizationalUnit"], ou: [jira.jiraId], description: [jira.name] },
    });
  }

  for (const app of odb.applications) {
    if (app.jiraId) {
      // 1. Keto tuple
      await httpRequest(`${KETO_WRITE_URL}/admin/relation-tuples`, "PUT", {
        namespace: "Resource",
        object: `app:${app.resourceId}`,
        relation: "parent",
        subject_set: { namespace: "Resource", object: `jira:${app.jiraId}` },
      });
      // 2. OpenLDAP DIT container
      ldapOps.push({
        type: "add",
        dn: `ou=${app.resourceId},ou=${app.jiraId},ou=resources,${LDAP_BASE_DN}`,
        attrs: { objectClass: ["organizationalUnit"], ou: [app.resourceId], description: [app.label] },
      });
    }
  }
  await sendLdapOps(ldapOps);
}

async function realizeApprovalDualWrite(reqItem, approvedBy) {
  const template = store.roleTemplates[reqItem.roleTemplateId];
  const userDn = `uid=${reqItem.userId},ou=users,${LDAP_BASE_DN}`;
  const containerDn =
    reqItem.targetType === "jira"
      ? `ou=${reqItem.targetId},ou=resources,${LDAP_BASE_DN}`
      : `ou=${reqItem.targetId},ou=JIRA-100,ou=resources,${LDAP_BASE_DN}`;
  const groupDn = `cn=${template.ldapGroupCn},${containerDn}`;

  // 1. Realize into Ory Keto
  await httpRequest(`${KETO_WRITE_URL}/admin/relation-tuples`, "PUT", {
    namespace: "Resource",
    object: `${reqItem.targetType}:${reqItem.targetId}`,
    relation: template.ketoRelation,
    subject_id: reqItem.userId,
  });

  // 2. Realize into OpenLDAP
  await ensureLdapBase();
  await sendLdapOps([
    {
      type: "add",
      dn: groupDn,
      attrs: { objectClass: ["groupOfNames"], cn: [template.ldapGroupCn], member: [userDn] },
    },
    {
      type: "modifyAdd",
      dn: groupDn,
      attr: "member",
      vals: [userDn],
    },
  ]);

  const auditEntry = {
    auditId: `aud-${Date.now()}`,
    requestId: reqItem.requestId,
    timestamp: new Date().toISOString(),
    action: "APPROVED_AND_REALIZED",
    userId: reqItem.userId,
    roleTemplateId: reqItem.roleTemplateId,
    target: `${reqItem.targetType}:${reqItem.targetId}`,
    approvedBy,
    targetsWritten: ["ory-keto", "openldap"],
  };
  store.approvalsAuditLog.push(auditEntry);
  return auditEntry;
}

const WEB_UI_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>AuthZ Config & Request Plane</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; background: #f8fafc; color: #0f172a; }
    h1 { margin-bottom: 0.25rem; }
    .sub { color: #475569; margin-bottom: 1.5rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 1.25rem; }
    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.25rem; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
    h2 { font-size: 1.1rem; margin-top: 0; border-bottom: 1px solid #f1f5f9; padding-bottom: 0.5rem; }
    label { display: block; font-size: 0.85rem; font-weight: 600; margin-top: 0.6rem; }
    input, select { width: 100%; padding: 0.45rem; margin-top: 0.2rem; border: 1px solid #cbd5e1; border-radius: 4px; box-sizing: border-box; }
    button { margin-top: 0.9rem; padding: 0.5rem 0.9rem; background: #2563eb; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; }
    button.approve { background: #16a34a; margin-top: 0; padding: 0.3rem 0.6rem; font-size: 0.8rem; }
    button.reject { background: #dc2626; margin-top: 0; padding: 0.3rem 0.6rem; font-size: 0.8rem; }
    pre { background: #0f172a; color: #e2e8f0; padding: 0.75rem; border-radius: 6px; font-size: 0.8rem; overflow-x: auto; max-height: 240px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 0.5rem; }
    th, td { text-align: left; padding: 0.45rem; border-bottom: 1px solid #e2e8f0; }
    .badge { padding: 0.15rem 0.45rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }
    .PENDING { background: #fef3c7; color: #92400e; }
    .APPROVED { background: #dcfce7; color: #166534; }
    .REJECTED { background: #fee2e2; color: #991b1b; }
  </style>
</head>
<body>
  <h1>AuthZ Config & Request Plane</h1>
  <div class="sub">Control Plane for Role Templates, Access Requests, and Dual-Write Realization (Ory Keto + OpenLDAP)</div>

  <div class="grid">
    <div class="card">
      <h2>1. Sync ODB Topology</h2>
      <p style="font-size:0.85rem;color:#475569;">Project Jira &rarr; Application hierarchy from Mock ODB into Ory Keto &amp; OpenLDAP.</p>
      <button onclick="syncOdb()">Sync ODB Topology Now</button>
      <pre id="odbBox">Loading ODB...</pre>
    </div>

    <div class="card">
      <h2>2. Request Access (User / App)</h2>
      <label>User ID</label>
      <input id="reqUser" value="alice" />
      <label>Role Template</label>
      <select id="reqTemplate"></select>
      <label>Target Type</label>
      <select id="reqTargetType">
        <option value="jira">jira (Inherits to all child apps)</option>
        <option value="app">app (Single application)</option>
      </select>
      <label>Target ID</label>
      <input id="reqTargetId" value="JIRA-100" />
      <label>Justification</label>
      <input id="reqJust" value="Deploy and rotate payment secrets" />
      <button onclick="submitRequest()">Submit Access Request</button>
    </div>

    <div class="card">
      <h2>3. Config Plane: Create Role Template</h2>
      <label>Template ID</label>
      <input id="tplId" placeholder="e.g. bar-operator" />
      <label>Description</label>
      <input id="tplDesc" placeholder="Grants operator access" />
      <label>Keto Relation</label>
      <input id="tplKeto" value="users" />
      <label>LDAP Group CN</label>
      <input id="tplLdap" placeholder="e.g. bar-operator" />
      <button onclick="createTemplate()">Save Role Template</button>
    </div>
  </div>

  <div class="card" style="margin-top:1.25rem;">
    <h2>4. Access Requests Queue (Approvals &rarr; Dual-Write Realization)</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>User</th><th>Template</th><th>Target</th><th>Justification</th><th>Status</th><th>Action</th></tr>
      </thead>
      <tbody id="reqTable"></tbody>
    </table>
  </div>

  <div class="card" style="margin-top:1.25rem;">
    <h2>5. Immutable Governance Audit Log</h2>
    <pre id="auditBox">[]</pre>
  </div>

  <script>
    async function refresh() {
      const [stateRes, odbRes] = await Promise.all([fetch('/state'), fetch('/odb-proxy')]);
      const state = await stateRes.json();
      const odb = await odbRes.json();
      document.getElementById('odbBox').textContent = JSON.stringify(odb, null, 2);

      const sel = document.getElementById('reqTemplate');
      const current = sel.value;
      sel.innerHTML = Object.values(state.roleTemplates)
        .map(t => '<option value="' + t.templateId + '">' + t.templateId + ' - ' + t.description + '</option>')
        .join('');
      if (current) sel.value = current;

      const tbody = document.getElementById('reqTable');
      tbody.innerHTML = state.accessRequests.map(r => {
        const actions = r.status === 'PENDING'
          ? '<button class="approve" onclick="decide(\\'' + r.requestId + '\\', \\'approve\\')">Approve</button> ' +
            '<button class="reject" onclick="decide(\\'' + r.requestId + '\\', \\'reject\\')">Reject</button>'
          : 'Reviewed by ' + (r.reviewedBy || '-');
        return '<tr><td>' + r.requestId + '</td><td>' + r.userId + '</td><td>' + r.roleTemplateId +
               '</td><td>' + r.targetType + ':' + r.targetId + '</td><td>' + r.justification +
               '</td><td><span class="badge ' + r.status + '">' + r.status + '</span></td><td>' + actions + '</td></tr>';
      }).join('');

      document.getElementById('auditBox').textContent = JSON.stringify(state.approvalsAuditLog, null, 2);
    }

    async function syncOdb() {
      await fetch('/sync-odb', { method: 'POST' });
      alert('ODB Topology synced to Ory Keto & OpenLDAP');
      refresh();
    }

    async function submitRequest() {
      await fetch('/requests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: document.getElementById('reqUser').value,
          roleTemplateId: document.getElementById('reqTemplate').value,
          targetType: document.getElementById('reqTargetType').value,
          targetId: document.getElementById('reqTargetId').value,
          justification: document.getElementById('reqJust').value
        })
      });
      refresh();
    }

    async function decide(id, action) {
      await fetch('/requests/' + id + '/' + action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewedBy: 'admin-ui' })
      });
      refresh();
    }

    async function createTemplate() {
      await fetch('/config/role-templates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          templateId: document.getElementById('tplId').value,
          description: document.getElementById('tplDesc').value,
          ketoRelation: document.getElementById('tplKeto').value,
          ldapGroupCn: document.getElementById('tplLdap').value
        })
      });
      refresh();
    }

    refresh();
  </script>
</body>
</html>`;

const server = http.createServer(async (req, res) => {
  // Serve Web UI
  if (req.url === "/" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "text/html" });
    return res.end(WEB_UI_HTML);
  }

  res.setHeader("Content-Type", "application/json");

  if (req.url === "/state" && req.method === "GET") {
    return res.end(JSON.stringify(store, null, 2));
  }

  if (req.url === "/odb-proxy" && req.method === "GET") {
    const odbRes = await httpRequest(`${ODB_URL}/odb`, "GET");
    return res.end(odbRes.body);
  }

  if (req.url === "/sync-odb" && req.method === "POST") {
    await syncTopologyDualWrite();
    return res.end(JSON.stringify({ status: "synced ODB topology to Ory Keto & OpenLDAP" }));
  }

  // Config Plane: Create/Update Role Template
  if (req.url === "/config/role-templates" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const tpl = JSON.parse(body);
      if (!tpl.templateId) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "templateId required" }));
      }
      store.roleTemplates[tpl.templateId] = tpl;
      res.writeHead(201);
      res.end(JSON.stringify(tpl));
    });
    return;
  }

  // Request Plane: Submit Access Request (PENDING)
  if (req.url === "/requests" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { userId, roleTemplateId, targetType, targetId, justification } = JSON.parse(body);
      if (!store.roleTemplates[roleTemplateId]) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: `Unknown roleTemplateId: ${roleTemplateId}` }));
      }
      const item = {
        requestId: `req-${Date.now()}`,
        createdAt: new Date().toISOString(),
        userId,
        roleTemplateId,
        targetType,
        targetId,
        justification: justification || "",
        status: "PENDING",
      };
      store.accessRequests.push(item);
      res.writeHead(201);
      res.end(JSON.stringify(item));
    });
    return;
  }

  if (req.url === "/requests" && req.method === "GET") {
    return res.end(JSON.stringify(store.accessRequests, null, 2));
  }

  // Request Plane: Approve or Reject a Request
  const match = req.url.match(/^\/requests\/([^/]+)\/(approve|reject)$/);
  if (match && req.method === "POST") {
    const [, requestId, decision] = match;
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      const { reviewedBy } = JSON.parse(body || "{}");
      const reqItem = store.accessRequests.find((r) => r.requestId === requestId);
      if (!reqItem) {
        res.writeHead(404);
        return res.end(JSON.stringify({ error: "Request not found" }));
      }
      if (reqItem.status !== "PENDING") {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: `Request already ${reqItem.status}` }));
      }

      reqItem.reviewedBy = reviewedBy || "approver";
      reqItem.reviewedAt = new Date().toISOString();

      if (decision === "reject") {
        reqItem.status = "REJECTED";
        store.approvalsAuditLog.push({
          auditId: `aud-${Date.now()}`,
          requestId: reqItem.requestId,
          timestamp: reqItem.reviewedAt,
          action: "REJECTED",
          userId: reqItem.userId,
          roleTemplateId: reqItem.roleTemplateId,
          target: `${reqItem.targetType}:${reqItem.targetId}`,
          reviewedBy: reqItem.reviewedBy,
        });
        return res.end(JSON.stringify(reqItem));
      }

      reqItem.status = "APPROVED";
      const audit = await realizeApprovalDualWrite(reqItem, reqItem.reviewedBy);
      res.end(JSON.stringify({ request: reqItem, realizationAudit: audit }));
    });
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(4002, () => console.log("Config & Request Plane (CLI + Web UI) running on :4002"));
