import { createHmac, timingSafeEqual } from "node:crypto";

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 14;

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];

    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

function sameValue(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function createSession(secret) {
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  const signature = createHmac("sha256", secret)
    .update(String(expiresAt))
    .digest("base64url");

  return `${expiresAt}.${signature}`;
}

export default async function handler(request, response) {
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    response.status(405).json({ error: "Method not allowed" });
    return;
  }

  const password = process.env.ARCHITECTURE_PASSWORD;
  const sessionSecret = process.env.ARCHITECTURE_SESSION_SECRET;

  if (!password || !sessionSecret) {
    response.status(503).json({ error: "Password protection is not configured" });
    return;
  }

  let body;
  try {
    body = JSON.parse(await readBody(request));
  } catch {
    response.status(400).json({ error: "Invalid request" });
    return;
  }

  if (typeof body.password !== "string" || !sameValue(body.password, password)) {
    response.status(401).json({ error: "Incorrect password" });
    return;
  }

  const secure = process.env.VERCEL ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `architecture_access=${createSession(sessionSecret)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}${secure}`,
  );
  response.status(200).json({ ok: true });
}
