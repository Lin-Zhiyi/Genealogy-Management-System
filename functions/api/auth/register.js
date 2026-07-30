// functions/api/auth/register.js
export async function onRequestPost(context) {
  const { request, env } = context;
  const { username, password, adminPassword } = await request.json();

  if (!username || !password || !adminPassword) {
    return new Response(JSON.stringify({ error: '所有字段都是必填的' }), { status: 400 });
  }

  // 从 KV 获取管理员账户数据
  const adminData = await env.USER_KV.get('user:admin');
  if (!adminData) {
    return new Response(JSON.stringify({ error: '管理员账户未配置，无法注册' }), { status: 500 });
  }

  let adminUser;
  try {
    adminUser = JSON.parse(adminData);
  } catch {
    return new Response(JSON.stringify({ error: '管理员数据损坏' }), { status: 500 });
  }

  // 验证管理员密码（与管理员当前密码一致）
  const adminHashParts = adminUser.password.split(':');
  if (adminHashParts.length !== 2) {
    return new Response(JSON.stringify({ error: '管理员密码格式错误' }), { status: 500 });
  }
  const [adminSalt, adminStoredHash] = adminHashParts;
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
    role: 'user'
  };

  await env.USER_KV.put(`user:${username}`, JSON.stringify(user));

  return new Response(JSON.stringify({ success: true, message: '注册成功，请登录' }), {
    status: 201,
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
