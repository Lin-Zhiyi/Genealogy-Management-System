// functions/api/admin/delete-user.js
export async function onRequestPost(context) {
  const { request, env } = context;

  // 验证管理员权限
  const tokenPayload = await getUserFromCookie(request, env.JWT_SECRET);
  if (!tokenPayload || tokenPayload.role !== 'admin') {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: '请求格式错误' }), { status: 400 });
  }

  const { username } = body;
  if (!username) {
    return new Response(JSON.stringify({ error: '缺少用户名' }), { status: 400 });
  }
  if (username === 'admin') {
    return new Response(JSON.stringify({ error: '不能删除管理员' }), { status: 403 });
  }

  const key = `user:${username}`;
  const exists = await env.USER_KV.get(key);
  if (!exists) {
    return new Response(JSON.stringify({ error: '用户不存在' }), { status: 404 });
  }

  await env.USER_KV.delete(key);
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// ---------- 工具函数（与 login.js 一致）----------
async function getUserFromCookie(request, secret) {
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  if (!tokenMatch) return null;
  try {
    const { payload } = await verifyToken(tokenMatch[1], secret);
    return payload;
  } catch {
    return null;
  }
}

async function verifyToken(token, secret) {
  const encoder = new TextEncoder();
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');
  const [headerB64, payloadB64, signatureB64] = parts;
  const signature = base64UrlDecode(signatureB64);
  const data = encoder.encode(`${headerB64}.${payloadB64}`);
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!valid) throw new Error('Signature invalid');
  const payloadBytes = base64UrlDecode(payloadB64);
  const payloadText = new TextDecoder().decode(payloadBytes);
  const payload = JSON.parse(payloadText);
  if (payload.exp && payload.exp < Date.now() / 1000) throw new Error('Token expired');
  return { payload };
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
