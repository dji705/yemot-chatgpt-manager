import { RESOURCE, ISSUER, READ_SCOPE, json } from "./_oauth.js";
export default function handler(req, res) {
  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" });
  return json(res, 200, { resource: RESOURCE, authorization_servers: [ISSUER], scopes_supported: [READ_SCOPE], resource_documentation: ISSUER });
}
