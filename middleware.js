import { next } from "@vercel/functions";

const encoder = new TextEncoder();

function readCookie(request, name) {
  const value = request.headers.get("cookie") || "";
  const prefix = `${name}=`;

  for (const item of value.split(";")) {
    const cookie = item.trim();
    if (cookie.startsWith(prefix)) {
      return cookie.slice(prefix.length);
    }
  }

  return null;
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;

  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }

  return difference === 0;
}

async function isValidSession(token, secret) {
  if (!token || !secret) return false;

  const separator = token.lastIndexOf(".");
  if (separator <= 0) return false;

  const expiresAt = Number(token.slice(0, separator));
  const signature = token.slice(separator + 1);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signed = await crypto.subtle.sign("HMAC", key, encoder.encode(String(expiresAt)));
  const expected = btoa(String.fromCharCode(...new Uint8Array(signed)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

  return constantTimeEqual(signature, expected);
}

export const config = {
  matcher: "/((?!api/login|access\\.html|favicon\\.ico).*)",
};

export default async function middleware(request) {
  const authenticated = await isValidSession(
    readCookie(request, "architecture_access"),
    process.env.ARCHITECTURE_SESSION_SECRET,
  );

  if (authenticated) return next();

  const requestedUrl = new URL(request.url);
  const accessUrl = new URL("/access.html", request.url);
  accessUrl.searchParams.set("next", `${requestedUrl.pathname}${requestedUrl.search}`);
  return Response.redirect(accessUrl, 303);
}
