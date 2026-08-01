// functions/api/auth/register.js

// 速率限制内存 Map
const rateLimitMap = new Map();

export async function onRequestPost(context) {
  const { request, env } = context;

  // 速率限制检查
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const windowMs = 60 * 1000;
  if (!rateLimitMap.has(clientIP)) {
    rateLimitMap.set(clientIP, { count: 1, resetAt: now + windowMs });
  } else {
    const entry = rateLimitMap.get(clientIP);
    if (now > entry.resetAt) {
      entry.count = 1;
      entry.resetAt = now + windowMs;
    } else {
      entry.count++;
      if (entry.count > 5) {
        return new Response(JSON.stringify({ error: '请求过于频繁，请稍后再试' }), {
          status: 429,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: '请求格式错误' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  const { username, password, adminPassword } = body;

  if (!username || !password || !adminPassword) {
    return new Response(JSON.stringify({ error: '所有字段都是必填的' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  // 服务端输入验证
  if (typeof username !== 'string' || typeof password !== 'string' || typeof adminPassword !== 'string') {
    return new Response(JSON.stringify({ error: '字段类型错误' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  if (username.length < 2 || username.length > 20) {
    return new Response(JSON.stringify({ error: '用户名需在2-20个字符之间' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  if (!/^[a-zA-Z0-9_\u4e00-\u9fff]+$/.test(username)) {
    return new Response(JSON.stringify({ error: '用户名只能包含中英文、数字和下划线' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  if (password.length < 6) {
    return new Response(JSON.stringify({ error: '密码至少6个字符' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  // 从 KV 获取管理员账户数据
  let adminData;
  try {
    adminData = await env.USER_KV.get('user:admin');
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器存储错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }

  if (!adminData) {
    return new Response(JSON.stringify({ error: '管理员账户未配置，无法注册' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }

  let adminUser;
  try {
    adminUser = JSON.parse(adminData);
  } catch {
    return new Response(JSON.stringify({ error: '管理员数据损坏' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }

  // 验证管理员密码
  const adminHashParts = adminUser.password.split(':');
  if (adminHashParts.length !== 2) {
    return new Response(JSON.stringify({ error: '管理员密码格式错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
  const [adminSalt, adminStoredHash] = adminHashParts;
  let adminHash;
  try {
    adminHash = await sha512(adminSalt + adminPassword);
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器内部错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }

  if (adminHash !== adminStoredHash) {
    return new Response(JSON.stringify({ error: '管理员密码错误' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
  }

  // 检查用户名是否已存在
  let existing;
  try {
    existing = await env.USER_KV.get(`user:${username}`);
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器存储错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }

  if (existing) {
    return new Response(JSON.stringify({ error: '用户名已存在' }), { status: 409, headers: { 'Content-Type': 'application/json' } });
  }

  // 生成盐和哈希
  let salt, hash;
  try {
    salt = generateSalt();
    hash = await sha512(salt + password);
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器内部错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }

  const user = {
    username,
    password: `${salt}:${hash}`,
    role: 'user'
  };

  try {
    await env.USER_KV.put(`user:${username}`, JSON.stringify(user));
  } catch (e) {
    return new Response(JSON.stringify({ error: '保存用户失败' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }

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
