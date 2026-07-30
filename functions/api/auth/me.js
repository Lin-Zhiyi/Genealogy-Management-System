// functions/api/auth/me.js
export async function onRequestGet(context) {
  const { request, env } = context;

  // 从 Cookie 中提取 token 并验证
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  if (!tokenMatch) {
    return new Response(JSON.stringify({ error: '未登录' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  try {
    const { payload } = await verifyToken(tokenMatch[1], env.JWT_SECRET);
    return new Response(JSON.stringify({ username: payload.username, role: payload.role }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: '令牌无效' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }
}

// 复用验证函数（与登录接口中的相同）
async function verifyToken(token, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const [headerB64, payloadB64, signatureB64] = parts;
  const signature = base64UrlToArrayBuffer(signatureB64);
  const data = encoder.encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!valid) throw new Error('Signature invalid');
  const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
  if (payload.exp && payload.exp < Date.now() / 1000) throw new Error('Token expired');
  return { payload };
}

function base64UrlToArrayBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
    .padEnd(base64url.length + (4 - base64url.length % 4) % 4, '=');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
