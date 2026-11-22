import { signed, json, oauthError } from "../_oauth.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return oauthError(res, 405, "invalid_request", "POST required");
  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body || {};
    const redirects = body.redirect_uris;
    if (!Array.isArray(redirects) || redirects.length < 1 || redirects.length > 10) return oauthError(res, 400, "invalid_client_metadata", "redirect_uris is required");
    for (const value of redirects) {
      let u; try { u = new URL(value); } catch { return oauthError(res, 400, "invalid_redirect_uri", "Invalid redirect URI"); }
      const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
      if (u.protocol !== "https:" && !(loopback && u.protocol === "http:")) return oauthError(res, 400, "invalid_redirect_uri", "HTTPS redirect URI required");
    }
    const client = {
      client_name: String(body.client_name || "ChatGPT MCP client").slice(0, 120),
      redirect_uris: redirects,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      created_at: Date.now()
    };
    const client_id = signed(client, "oauth-client");
    return json(res, 201, { client_id, client_id_issued_at: Math.floor(Date.now()/1000), client_name: client.client_name, redirect_uris: redirects, grant_types: client.grant_types, response_types: client.response_types, token_endpoint_auth_method: "none" });
  } catch (e) {
    return oauthError(res, 500, "server_error", e.message);
  }
}
