import { ISSUER, READ_SCOPE, json } from "../lib/oauth.js";
export default function handler(req, res) {
  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" });
  return json(res, 200, {
    issuer: ISSUER,
    authorization_endpoint: ISSUER + "/oauth/authorize",
    token_endpoint: ISSUER + "/oauth/token",
    registration_endpoint: ISSUER + "/oauth/register",
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [READ_SCOPE],
    client_id_metadata_document_supported: false,
    authorization_response_iss_parameter_supported: false
  });
}
