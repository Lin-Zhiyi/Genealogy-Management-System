// functions/api/auth/register.js
export async function onRequestPost(context) {
  const { request, env } = context;
  const { username, password, adminPassword } = await request.json();

  if (!username || !password || !adminPassword) {
    return new Response(JSON.stringify({ error: '所有字段都是必填的' }), { status: 400 });
  }

  // 验证管理员密码
  const adminHashParts = env.ADMIN_PASSWORD_HASH.split(':');
  if (adminHashParts.length !== 2) {
    return new Response(JSON.stringify({ error: '服务器配置错误' }), { status: 500 });
  }
  const adminSalt = adminHashParts[0];
  const adminStoredHash = adminHashParts[1];
  const adminHash = await sha512(adminSalt + adminPassword);
  if (adminHash !== adminStoredHash) {
    return new Response(JSON.stringify({ error: '管理员密码错误' }), { status: 403 });
  }

  // 检查用户名是否已存在
  const existing = await env.USER_KV.get(`user:${username}`);
  if (existing) {
    return new Response(JSON.stringify({ error: '用户名已存在' }), { status: 409 });
  }

  // 生成盐和哈希存储
  const salt = generateSalt();
  const hash = await sha512(salt + password);
  const user = {
    username,
    password: `${salt}:${hash}`,
    role: 'user' // 普通用户
  };

  await env.USER_KV.put(`user:${username}`, JSON.stringify(user));

  return new Response(JSON.stringify({ success: true, message: '注册成功，请登录' }), {
    status: 201,
    headers: { 'Content-Type': 'application/json' }
  });
}

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
