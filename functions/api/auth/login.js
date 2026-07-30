// functions/api/auth/login.js
export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. 检查必要的环境变量
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 16) {
    return new Response(JSON.stringify({ error: '服务器 JWT 密钥未配置或过短' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 2. 解析请求体
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: '请求格式错误' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const { username, password } = body;
  if (!username || !password) {
    return new Response(JSON.stringify({ error: '用户名和密码不能为空' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 3. 从 KV 读取用户数据
  let userData;
  try {
    userData = await env.USER_KV.get(`user:${username}`);
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器存储错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (!userData) {
    return new Response(JSON.stringify({ error: '用户名或密码错误' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 4. 解析用户数据
  let user;
  try {
    user = JSON.parse(userData);
  } catch {
    return new Response(JSON.stringify({ error: '用户数据损坏' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 5. 验证密码
  const parts = user.password.split(':');
  if (parts.length !== 2) {
    return new Response(JSON.stringify({ error: '用户密码格式错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  const [salt, storedHash] = parts;

  let inputHash;
  try {
    inputHash = await sha512(salt + password);
  } catch (e) {
    return new Response(JSON.stringify({ error: '服务器内部错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (inputHash !== storedHash) {
    return new Response(JSON.stringify({ error: '用户名或密码错误' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 6. 生成 JWT
  let token;
  try {
    token = await generateToken({ username, role: user.role }, env.JWT_SECRET, '24h');
  } catch (e) {
    return new Response(JSON.stringify({ error: `令牌生成失败: ${e.message}` }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 7. 设置 Cookie 并返回成功
  const headers = new Headers({
    'Content-Type': 'application/json',
    'Set-Cookie': `token=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
  });

  return new Response(JSON.stringify({ success: true }), { headers });
}

// ---------- 工具函数 ----------
async function sha512(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-512', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---------- 安全的 Base64URL 编码（避免 btoa 中文错误）----------
function base64urlEncode(str) {
  // 将字符串转换为 UTF-8 字节，再编码为 Base64，然后转为 Base64URL
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  // 使用 btoa 处理每个字节的字符，但需要将字节数组转为字符串（Latin1 逐个转换）
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// ---------- JWT 生成函数 ----------
async function generateToken(payload, secret, expiresIn) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (expiresIn.endsWith('h') ? parseInt(expiresIn) * 3600 : 86400);
  const fullPayload = { ...payload, iat: now, exp };

  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(fullPayload));
  const data = `${headerB64}.${payloadB64}`;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  // 将签名数组转为 Base64URL
  const signatureBytes = new Uint8Array(signature);
  let sigBinary = '';
  for (let i = 0; i < signatureBytes.length; i++) {
    sigBinary += String.fromCharCode(signatureBytes[i]);
  }
  const signatureB64 = btoa(sigBinary)
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}
