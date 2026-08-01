// functions/api/auth/register.js
const rateLimitMap = new Map();

export async function onRequestPost(context) {
  const { request, env } = context;

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
    return new Response(JSON.stringify({ error: '所有字段都是必填的' }), { status: 400 });
  }

  if (typeof username !== 'string' || typeof password !== 'string' || typeof adminPassword !== 'string') {
    return new Response(JSON.stringify({ error: '字段类型错误' }), { status: 400 });
  }
  if (username.length < 2 || username.length > 20) {
    return new Response(JSON.stringify({ error: '用户名需在2-20个字符之间' }), { status: 400 });
  }
  if (!/^[a-zA-Z0-9_\u4e00-\u9fff]+$/.test(username)) {
    return new Response(JSON.stringify({ error: '用户名只能包含中英文、数字和下划线' }), { status: 400 });
  }
  if (password.length < 6) {
    return new Response(JSON.stringify({ error: '密码至少6个字符' }), { status: 400 });
  }

  // 禁止注册 admin 用户名
  if (username === 'admin') {
    return new Response(JSON.stringify({ error: '不能注册管理员账号' }), { status: 403 });
  }

  // 验证管理员密码
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

  // 决定角色：编辑用户（editor）还是浏览用户（viewer）
  let role = 'viewer';
  try {
    const familyData = await env.genealogy_management_system.get('family-data');
    if (familyData) {
      const data = JSON.parse(familyData);
      if (data.families) {
        for (const fam of data.families) {
          if (memberNameExists(fam.root, username)) {
            role = 'editor';
            break;
          }
        }
      }
    }
  } catch (e) {
    // 如果读取族谱数据失败，默认设为 viewer
  }

  // 生成盐和哈希
  const salt = generateSalt();
  const hash = await sha512(salt + password);
  const user = {
    username,
    password: `${salt}:${hash}`,
    role
  };

  await env.USER_KV.put(`user:${username}`, JSON.stringify(user));

  return new Response(JSON.stringify({ success: true, message: '注册成功，请登录', role }), {
    status: 201,
    headers: { 'Content-Type': 'application/json' }
  });
}

// 工具函数：检查族谱中是否存在某个姓名
function memberNameExists(node, name) {
  if (!node.isRoot && node.name === name) return true;
  if (node.children) {
    for (const child of node.children) {
      if (memberNameExists(child, name)) return true;
    }
  }
  return false;
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
