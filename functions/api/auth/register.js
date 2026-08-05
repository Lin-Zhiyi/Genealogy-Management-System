// functions/api/auth/register.js
import {
  hashPassword,
  verifyPassword,
  checkRateLimit,
  generateSalt
} from '../../_utils/auth.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  const rateLimitResult = await checkRateLimit(
    env.USER_KV,
    `ratelimit:register:${clientIP}`,
    5,
    60 * 1000
  );
  if (!rateLimitResult.allowed) {
    return new Response(JSON.stringify({ error: '请求过于频繁，请稍后再试' }), {
      status: 429,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: '请求格式错误' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const { username, password, adminPassword } = body;
  if (!username || !password || !adminPassword) {
    return new Response(JSON.stringify({ error: '所有字段都是必填的' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (typeof username !== 'string' || typeof password !== 'string' || typeof adminPassword !== 'string') {
    return new Response(JSON.stringify({ error: '字段类型错误' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  if (username.length < 2 || username.length > 20) {
    return new Response(JSON.stringify({ error: '用户名需在2-20个字符之间' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  if (!/^[a-zA-Z0-9_\u4e00-\u9fff]+$/.test(username)) {
    return new Response(JSON.stringify({ error: '用户名只能包含中英文、数字和下划线' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  if (password.length < 6) {
    return new Response(JSON.stringify({ error: '密码至少6个字符' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (username === 'admin') {
    return new Response(JSON.stringify({ error: '不能注册管理员账号' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  let adminData;
  try {
    adminData = await env.USER_KV.get('user:admin');
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器存储错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  if (!adminData) {
    return new Response(JSON.stringify({ error: '管理员账户未配置，无法注册' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  let adminUser;
  try {
    adminUser = JSON.parse(adminData);
  } catch {
    return new Response(JSON.stringify({ error: '管理员数据损坏' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const adminPasswordValid = await verifyPassword(adminPassword, adminUser.password);
    if (!adminPasswordValid) {
      return new Response(JSON.stringify({ error: '管理员密码错误' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (e) {
    return new Response(JSON.stringify({ error: '管理员密码验证失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  let existing;
  try {
    existing = await env.USER_KV.get(`user:${username}`);
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器存储错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  if (existing) {
    return new Response(JSON.stringify({ error: '用户名已存在' }), {
      status: 409,
      headers: { 'Content-Type': 'application/json' }
    });
  }

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
  } catch (e) {}

  const hashedPassword = await hashPassword(password);

  const user = {
    username,
    password: hashedPassword,
    role,
    pwdVersion: 1,
    createdAt: Date.now()
  };

  try {
    await env.USER_KV.put(`user:${username}`, JSON.stringify(user));
  } catch (e) {
    return new Response(JSON.stringify({ error: '保存用户失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  return new Response(JSON.stringify({ success: true, message: '注册成功，请登录', role }), {
    status: 201,
    headers: { 'Content-Type': 'application/json' }
  });
}

function memberNameExists(node, name) {
  if (!node.isRoot && node.name === name) return true;
  if (node.children) {
    for (const child of node.children) {
      if (memberNameExists(child, name)) return true;
    }
  }
  return false;
}