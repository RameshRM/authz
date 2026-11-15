const http = require("http");

const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json");
  const caller = req.headers["x-caller-app"] || "unknown";

  if (req.url === "/bar/v1/orders" && req.method === "GET") {
    return res.end(
      JSON.stringify({
        service: "api-bar",
        endpoint: "/bar/v1/orders",
        verifiedCallerApp: caller,
        orders: [{ id: "ord-1", amount: 250 }, { id: "ord-2", amount: 900 }],
      })
    );
  }

  if (req.url === "/bar/v1/status" && req.method === "GET") {
    return res.end(
      JSON.stringify({
        service: "api-bar",
        endpoint: "/bar/v1/status",
        verifiedCallerApp: caller,
        status: "healthy",
      })
    );
  }

  res.end(
    JSON.stringify({
      service: "api-bar",
      endpoint: req.url,
      method: req.method,
      verifiedCallerApp: caller,
      message: "Granted by PBAC all-API policy",
    })
  );
});

server.listen(4004, () => console.log("Application Bar API running on :4004"));
