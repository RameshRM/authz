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

  if (req.url === "/odb/applications" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const app = JSON.parse(body);
      if (!app.resourceId || odb.applications.some((a) => a.resourceId === app.resourceId)) {
        res.writeHead(409);
        return res.end(JSON.stringify({ error: "resourceId must be unique and non-empty" }));
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
