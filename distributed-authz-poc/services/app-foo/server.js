const http = require("http");

const OIDC_URL = process.env.OIDC_URL || "http://mock-oidc:4000";
const GATEWAY_URL = process.env.GATEWAY_URL || "http://oathkeeper:4455";
const ODB_URL = process.env.ODB_URL || "http://mock-odb:4001";

function httpRequest(url, method, headers = {}, data = null) {
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
          ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload), ...headers }
          : headers,
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

  // Protected by Oathkeeper + Keto ('foo-secret' role)
  const secretMatch = req.url.match(/^\/foo\/secrets\/([a-zA-Z0-9_-]+)$/);
  if (secretMatch && req.method === "GET") {
    const appId = secretMatch[1];
    const userId = req.headers["x-user-id"] || "unknown";
    const odbRes = await httpRequest(`${ODB_URL}/odb`, "GET");
    const odb = JSON.parse(odbRes.body);
    const app = odb.applications.find((a) => a.resourceId === appId);
    if (!app) {
      res.writeHead(404);
      return res.end(JSON.stringify({ error: "Application not found" }));
    }
    return res.end(
      JSON.stringify({
        application: app.resourceId,
        jiraId: app.jiraId,
        accessedBy: userId,
        secrets: app.secrets,
      })
    );
  }

  // App-to-App call: Foo mints PBAC token (scope: bar:all) and calls Bar via Oathkeeper
  if (req.url === "/foo/call-bar" && req.method === "GET") {
    const tokenRes = await httpRequest(`${OIDC_URL}/token`, "POST", {}, {
      sub: "service-account-foo",
      azp: "app-foo",
      scope: "bar:all",
    });
    const { access_token } = JSON.parse(tokenRes.body);

    const barOrders = await httpRequest(`${GATEWAY_URL}/bar/v1/orders`, "GET", {
      Authorization: `Bearer ${access_token}`,
    });
    const barHealth = await httpRequest(`${GATEWAY_URL}/bar/v1/status`, "GET", {
      Authorization: `Bearer ${access_token}`,
    });

    return res.end(
      JSON.stringify({
        caller: "app-foo",
        policy: "pbac-foo-to-bar (all APIs)",
        barOrdersResponse: { status: barOrders.status, data: JSON.parse(barOrders.body || "{}") },
        barStatusResponse: { status: barHealth.status, data: JSON.parse(barHealth.body || "{}") },
      })
    );
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: "Not found in app-foo" }));
});

server.listen(4003, () => console.log("Application Foo running on :4003"));
