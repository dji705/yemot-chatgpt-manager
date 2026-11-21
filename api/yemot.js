import crypto from "node:crypto";

const API_BASE = "https://www.call2all.co.il/ym/api/";
const READ_ONLY = new Set(["GetSession","GetIVR2Dir","GetIVR2DirStats","GetFile","GetTextFile","CheckIfFileExists"]);
const MUTATING = new Set(["UpdateExtension","UploadTextFile","FileAction","SetPassword"]);
const ALLOWED = new Set([...READ_ONLY, ...MUTATING]);

function sign(value) {
  const secret = process.env.PLAN_SECRET;
  if (!secret) throw new Error("חסר PLAN_SECRET בהגדרות Vercel");
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}
function safeEqual(a,b) {
  const aa=Buffer.from(String(a||"")); const bb=Buffer.from(String(b||""));
  return aa.length===bb.length && crypto.timingSafeEqual(aa,bb);
}
function tokenFor(payload) {
  const body=Buffer.from(JSON.stringify(payload)).toString("base64url");
  return body+"."+sign(body);
}
function verifyPlan(token, command, params, deletionConfirmed) {
  if (!token || !process.env.PLAN_SECRET) return false;
  const [body,mac,...extra]=String(token).split(".");
  if (!body || !mac || extra.length || !safeEqual(mac,sign(body))) return false;
  let p; try { p=JSON.parse(Buffer.from(body,"base64url").toString("utf8")); } catch { return false; }
  if (p.exp < Date.now() || p.command!==command) return false;
  if (JSON.stringify(p.params)!==JSON.stringify(params)) return false;
  if (p.deletion && deletionConfirmed!=="אני מאשר מחיקה") return false;
  return true;
}
function cleanParams(input) {
  const out={};
  for (const [k,v] of Object.entries(input||{})) {
    if (["token","username","password","newPassword"].includes(k)) continue;
    if (v!==undefined && v!==null && typeof v!=="object") out[k]=String(v);
    else if (v && typeof v==="object") out[k]=v;
  }
  return out;
}
export default async function handler(req,res) {
  res.setHeader("Cache-Control","no-store");
  res.setHeader("X-Content-Type-Options","nosniff");
  if (req.method!=="POST") return res.status(405).json({error:"Method not allowed"});
  try {
    const body=typeof req.body==="string"?JSON.parse(req.body):req.body||{};
    const {mode="call",command,credentials={},params={},approvalToken,deletionConfirmed}=body;
    if (mode==="plan") {
      if (!MUTATING.has(command)) return res.status(400).json({error:"אפשר לאשר מראש רק פעולות שמשנות את המערכת"});
      const clean=cleanParams(params);
      const deletion=command==="FileAction" && String(params.action||"").toLowerCase().includes("delete");
      const payload={command,params:clean,deletion,exp:Date.now()+5*60*1000,nonce:crypto.randomUUID()};
      return res.status(200).json({approvalToken:tokenFor(payload),deletion,expiresInSeconds:300,summary:{command,params:clean}});
    }
    if (mode!=="call") return res.status(400).json({error:"מצב לא מוכר"});
    if (!ALLOWED.has(command)) return res.status(400).json({error:"הפקודה אינה מאושרת לשימוש"});
    if (MUTATING.has(command) && !verifyPlan(approvalToken,command,cleanParams(params),deletionConfirmed)) {
      return res.status(403).json({error:"נדרש אישור מפורש ועדכני לתוכנית הפעולה לפני ביצוע"});
    }
    const auth={};
    if (credentials.token) auth.token=String(credentials.token);
    else if (credentials.username && credentials.password) {
      // Login is performed for this request only; credentials and tokens are never logged or persisted.
      const login=await fetch(API_BASE+"Login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:String(credentials.username),password:String(credentials.password)})});
      const loginData=await login.json();
      if (!login.ok || loginData.responseStatus!=="OK" || !loginData.token) return res.status(401).json({error:loginData.message||"ההתחברות נכשלה"});
      auth.token=loginData.token;
    } else return res.status(400).json({error:"יש להזין טוקן או מספר מערכת וסיסמת ניהול"});
    const payload={...params,...auth};
    const upstream=await fetch(API_BASE+encodeURIComponent(command),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    const text=await upstream.text();
    let data; try { data=JSON.parse(text); } catch { data={raw:text}; }
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({error:e.message||"שגיאת שרת"});
  }
}
