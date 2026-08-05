// functions/api/auth/login.js
import {
  generateToken,
  verifyPassword,
  hashPassword,
  checkRateLimit,
  base64UrlEncode,
  base64UrlDecode
} from '../../_utils/auth.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  // 速率限制（基于 KV，支持多实例）
  const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  const rateLimitResult = await checkRateLimit(
    env.USER_KV,
    `ratelimit:login:${clientIP}`,
    10,        // 每分钟最多 10 次
    60 * 1000  // 60 秒窗口
  );
  if (!rateLimitResult.allowed) {
    return new Response(JSON.stringify({ error: '请求过于频繁，请稍后再试' }), {
      status: 429,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 检查环境变量
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 16) {
    return new Response(JSON.stringify({ error: '服务器配置错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 解析请求体
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: '请求格式错误' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  const { username, password } = body;
  if (!username || !password) {
    return new Response(JSON.stringify({ error: '用户名和密码不能为空' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 输入验证
  if (typeof username !== 'string' || typeof password !== 'string') {
    return new Response(JSON.stringify({ error: '字段类型错误' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }
  if (username.length < 2 || username.length > 20) {
    return new Response(JSON.stringify({ error: '用户名长度不正确' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }
  if (password.length < 6) {
    return new Response(JSON.stringify({ error: '密码至少6位' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 从 KV 读取用户数据
  let userData;
  try {
    userData = await env.USER_KV.get(`user:${username}`);
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  if (!userData) {
    return new Response(JSON.stringify({ error: '用户名或密码错误' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 解析用户数据
  let user;
  try {
    user = JSON.parse(userData);
  } catch {
    return new Response(JSON.stringify({ error: '用户数据损坏' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 验证密码（兼容旧 SHA-512 格式和新 PBKDF2 格式）
  let passwordValid = false;
  try {
    passwordValid = await verifyPassword(password, user.password);
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器内部错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  if (!passwordValid) {
    return new Response(JSON.stringify({ error: '用户名或密码错误' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 如果是旧格式密码，自动升级为 PBKDF2
  if (!user.password.startsWith('pbkdf2:')) {
    try {
      const newHash = await hashPassword(password);
      user.password = newHash;
      await env.USER_KV.put(`user:${username}`, JSON.stringify(user));
    } catch (e) {
      // 升级失败不影响登录
      console.warn('密码升级失败:', e.message);
    }
  }

  // 确保用户有密码版本号
  if (user.pwdVersion === undefined) {
    user.pwdVersion = 1;
    try {
      await env.USER_KV.put(`user:${username}`, JSON.stringify(user));
    } catch (e) {}
  }

  // 生成 JWT（包含角色和密码版本号）
  let token;
  try {
    token = await generateToken(
      { username, role: user.role || 'viewer', pwdVersion: user.pwdVersion || 1 },
      env.JWT_SECRET,
      '24h'
    );
  } catch (e) {
    return new Response(JSON.stringify({ error: '令牌生成失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Set-Cookie': `token=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
  });

  return new Response(JSON.stringify({ success: true }), { headers });
}
