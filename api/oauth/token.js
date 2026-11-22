import crypto from "node:crypto";
import { RESOURCE, validClient, verifySigned, issueAccess, issueRefresh, challengeFor, readForm, json, oauthError, consumeOnce } from "../../lib/oauth.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return oauthError(res, 405, "invalid_request", "POST required");
  const p = readForm(req);
  try {
    if (p.grant_type === "authorization_code") {
      const code = verifySigned(p.code, "oauth-code");
      if (!code || code.typ !== "code" || code.exp < Date.now()) return oauthError(res, 400, "invalid_grant", "Authorization code expired or invalid");
      const client = validClient(p.client_id);
      if (!client || code.client_id !== p.client_id || !client.redirect_uris.includes(p.redirect_uri) || code.redirect_uri !== p.redirect_uri) return oauthError(res, 400, "invalid_grant", "Client or redirect URI mismatch");
      if (!p.code_verifier || !/^[A-Za-z0-9._~-]{43,128}$/.test(p.code_verifier) || challengeFor(p.code_verifier) !== code.challenge) return oauthError(res, 400, "invalid_grant", "PKCE verification failed");
      if (code.resource !== RESOURCE || p.resource !== RESOURCE) return oauthError(res, 400, "invalid_target", "Resource mismatch");
      if (!await consumeOnce("oauth:code:" + crypto.createHash("sha256").update(p.code).digest("hex"), 300)) return oauthError(res, 400, "invalid_grant", "Authorization code already used");
      const payload = { sub: code.username, yemot: code.yemot, aud: RESOURCE, scope: code.scope, client_id: p.client_id };
      return json(res, 200, { access_token: issueAccess(payload), token_type: "Bearer", expires_in: 3600, refresh_token: issueRefresh(payload), scope: code.scope });
    }
    if (p.grant_type === "refresh_token") {
      const refresh = verifySigned(p.refresh_token, "oauth-refresh");
      if (!refresh || refresh.typ !== "refresh" || refresh.exp < Date.now() || refresh.aud !== RESOURCE || p.resource !== RESOURCE || refresh.client_id !== p.client_id) return oauthError(res, 400, "invalid_grant", "Refresh token expired or invalid");
      const client = validClient(p.client_id);
      if (!client) return oauthError(res, 400, "invalid_client", "Unknown client");
      if (!await consumeOnce("oauth:refresh:" + crypto.createHash("sha256").update(p.refresh_token).digest("hex"), 30 * 24 * 60 * 60)) return oauthError(res, 400, "invalid_grant", "Refresh token already used");
      const payload = { sub: refresh.sub, yemot: refresh.yemot, aud: RESOURCE, scope: refresh.scope, client_id: p.client_id };
      return json(res, 200, { access_token: issueAccess(payload), token_type: "Bearer", expires_in: 3600, refresh_token: issueRefresh(payload), scope: refresh.scope });
    }
    return oauthError(res, 400, "unsupported_grant_type", "Only authorization_code and refresh_token are supported");
  } catch (e) { return oauthError(res, 500, "server_error", e.message); }
}
