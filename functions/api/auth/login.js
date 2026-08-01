// functions/api/auth/login.js

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
          headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
      }
    }
  }

  // 检查环境变量
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 16) {
    return new Response(JSON.stringify({ error: '服务器 JWT 密钥未配置或过短' }), {
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
    return new Response(JSON.stringify({ error: '服务器存储错误' }), {
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

  // 验证密码
  const parts = user.password.split(':');
  if (parts.length !== 2) {
    return new Response(JSON.stringify({ error: '用户密码格式错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }
  const [salt, storedHash] = parts;

  let inputHash;
  try {
    inputHash = await sha512(salt + password);
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器内部错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  if (inputHash !== storedHash) {
    return new Response(JSON.stringify({ error: '用户名或密码错误' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 生成 JWT
  let token;
  try {
    token = await generateToken({ username, role: user.role }, env.JWT_SECRET, '24h');
  } catch (e) {
    return new Response(JSON.stringify({ error: `令牌生成失败: ${e.message}` }), {
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

// ---------- SHA-512 ----------
async function sha512(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-512', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------- JWT 生成（完全支持 UTF-8）----------
async function generateToken(payload, secret, expiresIn) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (expiresIn.endsWith('h') ? parseInt(expiresIn) * 3600 : 86400);
  const fullPayload = { ...payload, iat: now, exp };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(fullPayload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

function base64UrlEncode(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// ---------- JWT 验证（与中间件一致）----------
async function verifyToken(token, secret) {
  const encoder = new TextEncoder();
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');

  const [headerB64, payloadB64, signatureB64] = parts;
  const signature = base64UrlDecode(signatureB64);
  const data = encoder.encode(`${headerB64}.${payloadB64}`);

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
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
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
