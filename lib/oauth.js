import crypto from "node:crypto";

export const BASE_URL = process.env.PUBLIC_BASE_URL || "https://yemot-chatgpt-manager1.vercel.app";
export const RESOURCE = BASE_URL + "/api/mcp";
export const ISSUER = BASE_URL;
export const READ_SCOPE = "yemot:read";
export const OFFLINE_SCOPE = "offline_access";
export const OAUTH_SCOPE = READ_SCOPE + " " + OFFLINE_SCOPE;

function secret() {
  const value = process.env.OAUTH_SECRET;
  if (!value || value.length < 32) throw new Error("OAUTH_SECRET must be set to a random secret of at least 32 characters");
  return value;
}
function b64(value) { return Buffer.from(value).toString("base64url"); }
function unb64(value) { return Buffer.from(value, "base64url").toString("utf8"); }
function mac(input) { return crypto.createHmac("sha256", secret()).update(input).digest("base64url"); }
export function signed(payload, purpose) {
  const body = b64(JSON.stringify(payload));
  return body + "." + mac(purpose + "." + body);
}
export function verifySigned(token, purpose) {
  if (typeof token !== "string" || token.length > 12000) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const expected = mac(purpose + "." + parts[0]);
  const a = Buffer.from(parts[1]); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { return JSON.parse(unb64(parts[0])); } catch { return null; }
}
export function seal(value) {
  const key = crypto.createHash("sha256").update(secret()).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map(x => x.toString("base64url")).join(".");
}
export function unseal(value) {
  const [iv, tag, encrypted, ...extra] = String(value || "").split(".");
  if (!iv || !tag || !encrypted || extra.length) throw new Error("Invalid encrypted credential");
  const key = crypto.createHash("sha256").update(secret()).digest();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(encrypted, "base64url")), decipher.final()]).toString("utf8");
}
export function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(JSON.stringify(body));
}
export function readForm(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const raw = typeof req.body === "string" ? req.body : "";
  return Object.fromEntries(new URLSearchParams(raw));
}
export function issueCode(data) {
  return signed({ ...data, typ: "code", exp: Date.now() + 5 * 60 * 1000, nonce: crypto.randomUUID() }, "oauth-code");
}
export function issueAccess(data) {
  return signed({ ...data, typ: "access", exp: Date.now() + 60 * 60 * 1000, nonce: crypto.randomUUID() }, "oauth-access");
}
export function issueRefresh(data) {
  return signed({ ...data, typ: "refresh", exp: Date.now() + 30 * 24 * 60 * 60 * 1000, nonce: crypto.randomUUID() }, "oauth-refresh");
}
export function validClient(clientId) {
  const client = verifySigned(clientId, "oauth-client");
  if (!client || !Array.isArray(client.redirect_uris) || !client.redirect_uris.length) return null;
  return client;
}
export function challengeFor(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

export async function consumeOnce(key, ttlSeconds) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error("OAuth requires UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN");
  const endpoint = url.replace(/\/$/, "") + "/set/" + encodeURIComponent(key) + "/" + encodeURIComponent("1") + "?EX=" + ttlSeconds + "&NX";
  const response = await fetch(endpoint, { method: "POST", headers: { Authorization: "Bearer " + token } });
  if (!response.ok) throw new Error("OAuth one-time token storage unavailable");
  const data = await response.json();
  return data.result === "OK";
}

export function oauthError(res, status, error, description) {
  return json(res, status, { error, error_description: description });
}
