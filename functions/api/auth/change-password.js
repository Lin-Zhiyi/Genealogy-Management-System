// functions/api/auth/change-password.js
export async function onRequestPost(context) {
  const { request, env } = context;

  // 验证用户登录态
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  if (!tokenMatch) {
    return new Response(JSON.stringify({ error: '未登录' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  let username;
  try {
    const { payload } = await verifyToken(tokenMatch[1], env.JWT_SECRET);
    username = payload.username;
  } catch (e) {
    return new Response(JSON.stringify({ error: '令牌无效' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  // 读取请求体
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: '请求格式错误' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const { oldPassword, newPassword } = body;
  if (!oldPassword || !newPassword) {
    return new Response(JSON.stringify({ error: '旧密码和新密码不能为空' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  if (newPassword.length < 4) {
    return new Response(JSON.stringify({ error: '新密码至少4个字符' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  // 获取用户数据
  const userData = await env.USER_KV.get(`user:${username}`);
  if (!userData) {
    return new Response(JSON.stringify({ error: '用户不存在' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
  }
  const user = JSON.parse(userData);

  // 验证旧密码
  const [salt, storedHash] = user.password.split(':');
  const oldHash = await sha512(salt + oldPassword);
  if (oldHash !== storedHash) {
    return new Response(JSON.stringify({ error: '旧密码错误' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
  }

  // 生成新盐和哈希
  const newSalt = generateSalt();
  const newHash = await sha512(newSalt + newPassword);
  user.password = `${newSalt}:${newHash}`;

  // 保存到 KV
  await env.USER_KV.put(`user:${username}`, JSON.stringify(user));

  return new Response(JSON.stringify({ success: true, message: '密码修改成功' }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// ---------- 工具函数 ----------
async function sha512(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-512', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateSalt() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// ---------- JWT 验证函数（与中间件一致）----------
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
  if (parts.length !== 3) throw new Error('Invalid token format');

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
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
