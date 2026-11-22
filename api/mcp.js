import { RESOURCE, READ_SCOPE, verifySigned, unseal } from "./_oauth.js";

const API_BASE = "https://www.call2all.co.il/ym/api/";
const PROTOCOL_VERSION = "2025-03-26";

const TOOLS = [
  {
    name: "yemot_get_session",
    description: "קבלת פרטי מערכת ימות המשיח המחוברת. מחזיר רק פרטים בסיסיים שאינם כוללים פרטי חיוב או סיסמאות.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "yemot_list_branches",
    description: "קבלת רשימת הקבצים והתיקיות בשלוחה בימות המשיח. נתיב ברירת מחדל: ivr2:/",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "נתיב, לדוגמה ivr2:/ או ivr2:/1" } },
      additionalProperties: false
    }
  },
  {
    name: "yemot_branch_stats",
    description: "קבלת מידע כללי על שלוחה במערכת.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "נתיב השלוחה, לדוגמה ivr2:/1" } },
      required: ["path"],
      additionalProperties: false
    }
  },
  {
    name: "yemot_read_text_file",
    description: "קריאת קובץ טקסט במערכת, למשל ext.ini.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "נתיב מלא לקובץ, לדוגמה ivr2:/1/ext.ini" } },
      required: ["path"],
      additionalProperties: false
    }
  },
  {
    name: "yemot_file_info",
    description: "קבלת מידע על קובץ בודד.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "נתיב מלא לקובץ" } },
      required: ["path"],
      additionalProperties: false
    }
  },
  {
    name: "yemot_check_file",
    description: "בדיקה האם קובץ קיים במערכת.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "נתיב מלא לקובץ" } },
      required: ["path"],
      additionalProperties: false
    }
  }
];
for (const tool of TOOLS) tool.securitySchemes = [{ type: "oauth2", scopes: [READ_SCOPE] }];

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(JSON.stringify(body));
}

function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

async function yemotCall(command, token, params = {}) {
  const response = await fetch(API_BASE + command, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...params, token })
  });
  const raw = await response.text();
  let data;
  try { data = JSON.parse(raw); } catch { data = { raw }; }
  if (!response.ok || data?.responseStatus === "ERROR" || data?.responseStatus === "FORBIDDEN" || data?.responseStatus === "EXCEPTION") {
    throw new Error(data?.message || data?.error || `שגיאה מימות המשיח (HTTP ${response.status})`);
  }
  return data;
}

async function runTool(name, args, token) {
  const path = typeof args?.path === "string" ? args.path.trim() : "";
  switch (name) {
    case "yemot_get_session": {
      const d = await yemotCall("GetSession", token);
      return {
        responseStatus: d.responseStatus,
        name: d.name,
        username: d.username,
        yemotAPIVersion: d.yemotAPIVersion,
        units: d.units
      };
    }
    case "yemot_list_branches":
      return yemotCall("GetIVR2Dir", token, { path: path || "ivr2:/" });
    case "yemot_branch_stats":
      if (!path) throw new Error("חובה לציין נתיב שלוחה");
      return yemotCall("GetIVR2DirStats", token, { path });
    case "yemot_read_text_file":
      if (!path) throw new Error("חובה לציין נתיב קובץ");
      return yemotCall("GetTextFile", token, { path });
    case "yemot_file_info":
      if (!path) throw new Error("חובה לציין נתיב קובץ");
      return yemotCall("GetFile", token, { path });
    case "yemot_check_file":
      if (!path) throw new Error("חובה לציין נתיב קובץ");
      return yemotCall("CheckIfFileExists", token, { path });
    default:
      throw new Error("הכלי המבוקש אינו קיים");
  }
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, { error: "Method not allowed" });
  }

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return json(res, 400, rpcError(null, -32700, "Invalid JSON")); }
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return json(res, 400, rpcError(null, -32600, "Invalid Request"));

  const { id, method, params = {} } = body;
  if (body.jsonrpc !== "2.0" || typeof method !== "string") return json(res, 400, rpcError(id, -32600, "Invalid Request"));

  if (method === "notifications/initialized" || method === "notifications/cancelled") {
    res.statusCode = 202;
    res.setHeader("Cache-Control", "no-store");
    return res.end();
  }

  if (method === "initialize") {
    return json(res, 200, {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "yemot-ivr-manager", version: "0.1.0" },
        instructions: "מנהל ימות המשיח בעברית. בשלב זה זמינים כלי קריאה בלבד; אין לבצע שינוי במערכת דרך השרת."
      }
    });
  }

  if (method === "ping") return json(res, 200, { jsonrpc: "2.0", id, result: {} });

  if (method === "tools/list") {
    return json(res, 200, { jsonrpc: "2.0", id, result: { tools: TOOLS } });
  }

  if (method === "tools/call") {
    const auth = String(req.headers.authorization || "");
    const match = auth.match(/^Bearer\\s+(.+)$/i);
    const challenge = 'Bearer resource_metadata="https://yemot-chatgpt-manager1.vercel.app/.well-known/oauth-protected-resource", scope="' + READ_SCOPE + '"';
    if (!match) {
      res.setHeader("WWW-Authenticate", challenge);
      return json(res, 401, rpcError(id, -32001, "נדרשת התחברות OAuth לימות המשיח"));
    }
    const access = verifySigned(match[1].trim(), "oauth-access");
    if (!access || access.typ !== "access" || access.exp < Date.now() || access.aud !== RESOURCE || !String(access.scope || "").split(" ").includes(READ_SCOPE)) {
      res.setHeader("WWW-Authenticate", challenge);
      return json(res, 401, rpcError(id, -32001, "אסימון הגישה אינו תקף או שפג תוקפו"));
    }
    let yemotToken;
    try { yemotToken = unseal(access.yemot); }
    catch { return json(res, 401, rpcError(id, -32001, "לא ניתן לאמת את פרטי ההתחברות")); }
    const name = params?.name;
    const args = params?.arguments || {};
    try {
      const result = await runTool(name, args, yemotToken);
      return json(res, 200, {
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], structuredContent: result, isError: false }
      });
    } catch (error) {
      return json(res, 200, {
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: error?.message || "שגיאה לא ידועה" }], isError: true }
      });
    }
  }

  if (id === undefined) {
    res.statusCode = 202;
    res.setHeader("Cache-Control", "no-store");
    return res.end();
  }
  return json(res, 200, rpcError(id, -32601, "Method not found"));
}
