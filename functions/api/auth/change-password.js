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

// 工具函数
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

// 验证 token（与 me.js 中的相同）
async function verifyToken(token, secret) { /* 同上 */ }
// 请把 me.js 中的 verifyToken 和 base64UrlToArrayBuffer 复制过来
