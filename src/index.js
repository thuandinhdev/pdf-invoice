
import {
  AuthorizationError,
  OAuthAuthorizationServer,
} from "@cloudflare/workers-oauth-provider";
import { WorkerEntrypoint } from "cloudflare:workers";

const SCOPES = ["mcp:read"];

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);
}

function htmlResponse(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://pdf-invoice-oauth.thuandinhdev.workers.dev https://chatgpt.com; base-uri 'none'; frame-ancestors 'none'",
      ...extraHeaders,
    },
  });
}


    

function errorPage(message, status = 400) {
  return htmlResponse(
    `<!doctype html>
<html lang="vi">
<head><meta charset="utf-8"><title>Lỗi cấp quyền</title></head>
<body>
<h1>Không thể tiếp tục cấp quyền</h1>
<p>${escapeHtml(message)}</p>
</body></html>`,
    status,
  );
}

function authorizationPage(query) {
  return `<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PDF Invoice Reader</title>
<style>
body{font:16px system-ui,sans-serif;max-width:520px;margin:48px auto;padding:0 18px;color:#222}
main{border:1px solid #ddd;border-radius:12px;padding:24px}
label{display:block;margin:18px 0 6px}
input{box-sizing:border-box;width:100%;padding:12px;border:1px solid #aaa;border-radius:8px}
button{margin-top:18px;padding:12px 18px;border:0;border-radius:8px;background:#1f6feb;color:white;font-weight:600}
</style>
</head>
<body>
<main>
<h1>PDF Invoice Reader</h1>
<p>Nhập mật khẩu cấp quyền để cho phép ChatGPT truy cập các công cụ hóa đơn chỉ đọc.</p>
<form method="post" action="/authorize/approve" target="_top">
<input type="hidden" name="auth_query" value="${escapeHtml(query)}">
<label for="passphrase">Mật khẩu cấp quyền</label>
<input id="passphrase" name="passphrase" type="password" autocomplete="current-password" required>
<button type="submit">Cho phép truy cập chỉ đọc</button>
</form>
<p><small>Quyền được cấp giới hạn ở phạm vi mcp:read.</small></p>
</main>
</body>
</html>`;
}

function createOAuthServer(env) {
  return new OAuthAuthorizationServer({
    issuer: env.ISSUER,
    resources: [env.MCP_SERVER_URL],
    scopesSupported: SCOPES,
    clientIdMetadataDocumentEnabled: true,
  });
}

async function handleAuthorize(request, env, oauth) {
  try {
    await oauth.parseAuthRequest(request);
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return errorPage(
        error.description || "Yêu cầu OAuth không hợp lệ.",
      );
    }
    throw error;
  }

  const query = new URL(request.url).searchParams.toString();
  return htmlResponse(authorizationPage(query));
}

async function handleApprove(request, env, oauth) {
  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: "POST" },
    });
  }

  if (!env.ADMIN_PASSWORD) {
    return errorPage(
      "Thiếu cấu hình bí mật ADMIN_PASSWORD trên Cloudflare.",
      503,
    );
  }

  const form = await request.formData();
  const passphrase = String(form.get("passphrase") || "");
  const authQuery = String(form.get("auth_query") || "");

  if (!authQuery || authQuery.length > 6000) {
    return errorPage("Yêu cầu cấp quyền bị thiếu hoặc quá dài.");
  }

  const supplied = new TextEncoder().encode(passphrase);
  const expected = new TextEncoder().encode(env.ADMIN_PASSWORD);

  let difference = supplied.length ^ expected.length;
  const length = Math.max(supplied.length, expected.length);

  for (let i = 0; i < length; i++) {
    difference |= (supplied[i] || 0) ^ (expected[i] || 0);
  }

  if (difference !== 0) {
    return errorPage("Mật khẩu cấp quyền không chính xác.", 401);
  }

  // Parse lại yêu cầu gốc để kiểm tra redirect URI, client và PKCE.
  const reconstructedUrl = new URL("/authorize", env.ISSUER);
  reconstructedUrl.search = authQuery;

  const reconstructed = new Request(reconstructedUrl, {
    method: "GET",
  });

  let authRequest;

  try {
    authRequest = await oauth.parseAuthRequest(reconstructed);
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return errorPage(
        error.description || "Yêu cầu OAuth không hợp lệ.",
      );
    }
    throw error;
  }

  const client = await oauth.lookupClient(authRequest.clientId);

  if (!client) {
    return errorPage("Không tìm thấy OAuth client.");
  }

  const requestedScopes = Array.isArray(authRequest.scope)
    ? authRequest.scope
    : String(authRequest.scope || "").split(/\s+/).filter(Boolean);

  const grantedScopes = requestedScopes.filter(
    (scope) => SCOPES.includes(scope),
  );

  if (!grantedScopes.includes("mcp:read")) {
    return errorPage("Client chưa yêu cầu phạm vi mcp:read.");
  }

  const { redirectTo } = await oauth.completeAuthorization({
    request: authRequest,
    userId: "invoice-reader-admin",
    metadata: {
      clientName: client.clientName || "ChatGPT",
    },
    scope: grantedScopes,
    props: {
      userId: "invoice-reader-admin",
      access: "read-only",
    },
  });

  return Response.redirect(redirectTo, 302);
}

export default class PdfInvoiceOAuth extends WorkerEntrypoint {
  async fetch(request) {
    const oauthServer = createOAuthServer(this.env);
    const oauth = oauthServer.getOAuthApi(this.env);
    const url = new URL(request.url);

    if (url.pathname === "/authorize") {
      if (request.method !== "GET") {
        return new Response("Method not allowed", {
          status: 405,
          headers: { Allow: "GET" },
        });
      }

      return handleAuthorize(request, this.env, oauth);
    }

    if (url.pathname === "/authorize/approve") {
      return handleApprove(request, this.env, oauth);
    }

    return oauthServer.fetch(request, this.env, this.ctx);
  }

  validateToken(resource, token) {
    return createOAuthServer(this.env).validateToken(
      resource,
      token,
      this.env,
    );
  }
}
