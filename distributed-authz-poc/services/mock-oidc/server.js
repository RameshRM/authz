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
