import { BASE_URL, RESOURCE, READ_SCOPE, validClient, issueCode, readForm, json } from "../_oauth.js";

const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function page(res, params, error = "") {
  const fields = ["client_id","redirect_uri","response_type","state","code_challenge","code_challenge_method","resource","scope"];
  const hidden = fields.map(k => `<input type="hidden" name="${k}" value="${esc(params[k] || "")}">`).join("");
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  res.end(`<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>חיבור ימות המשיח</title><style>body{font-family:Arial,sans-serif;background:#f4f6fa;margin:0;padding:24px}.box{max-width:420px;margin:7vh auto;background:white;padding:28px;border-radius:16px;box-shadow:0 8px 35px #0001}h2{margin-top:0}label{display:block;margin:16px 0 6px}input{box-sizing:border-box;width:100%;padding:13px;border:1px solid #ccd2dc;border-radius:8px;font-size:16px}button{margin-top:22px;width:100%;padding:14px;background:#1457c5;color:white;border:0;border-radius:8px;font-size:16px}.err{color:#b00020}</style><div class="box"><h2>התחברות לימות המשיח</h2><p>הזן פרטי התחברות לניהול המערכת. הפרטים משמשים לאימות מול ימות המשיח ואינם נשמרים כטקסט גלוי.</p>${error ? `<p class="err">${esc(error)}</p>` : ""}<form method="post" action="/oauth/authorize">${hidden}<label>מספר מערכת / שם משתמש</label><input name="username" autocomplete="username" required><label>סיסמת ניהול</label><input name="password" type="password" autocomplete="current-password" required><button type="submit">התחבר ואשר גישה לקריאה</button></form><p style="font-size:12px;color:#667">ההרשאה הנוכחית מאפשרת קריאת מידע בלבד.</p></div></html>`);
}
export default async function handler(req, res) {
  if (req.method === "GET") {
    const p = req.query || {};
    const client = validClient(p.client_id);
    if (p.response_type !== "code" || !client || !client.redirect_uris.includes(p.redirect_uri) || p.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(p.code_challenge || "") || (p.resource && p.resource !== RESOURCE)) return json(res, 400, { error: "invalid_request", error_description: "Invalid OAuth authorization request" });
    return page(res, { ...p, resource: RESOURCE, scope: READ_SCOPE });
  }
  if (req.method !== "POST") return json(res, 405, { error: "method_not_allowed" });
  const p = readForm(req);
  const client = validClient(p.client_id);
  if (!client || !client.redirect_uris.includes(p.redirect_uri) || p.response_type !== "code" || p.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(p.code_challenge || "") || (p.resource && p.resource !== RESOURCE)) return json(res, 400, { error: "invalid_request" });
  const username = String(p.username || "").trim();
  const password = String(p.password || "");
  if (!username || !password || username.length > 100 || password.length > 300) return page(res, p, "יש להזין מספר מערכת וסיסמה תקינים");
  try {
    const response = await fetch("https://www.call2all.co.il/ym/api/Login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
    const data = await response.json();
    if (!response.ok || data.responseStatus !== "OK" || !data.token) return page(res, p, data.message || "ההתחברות לימות המשיח נכשלה");
    const code = issueCode({ client_id: p.client_id, redirect_uri: p.redirect_uri, challenge: p.code_challenge, resource: RESOURCE, scope: READ_SCOPE, yemot: (await import("../_oauth.js")).seal(data.token), username: data.username || username });
    const target = new URL(p.redirect_uri);
    target.searchParams.set("code", code);
    if (p.state) target.searchParams.set("state", p.state);
    res.statusCode = 302; res.setHeader("Location", target.toString()); res.setHeader("Cache-Control", "no-store"); return res.end();
  } catch (e) { return page(res, p, "שגיאה בהתחברות. נסה שוב."); }
}
