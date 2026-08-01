// functions/api/admin.js
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  // 验证管理员权限
  const tokenPayload = await getUserFromCookie(request, env.JWT_SECRET);
  if (!tokenPayload || tokenPayload.role !== 'admin') {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 获取非管理员用户列表
  if (url.pathname === '/api/admin/users' && request.method === 'GET') {
    try {
      const list = await env.USER_KV.list({ prefix: 'user:' });
      const users = [];
      for (const key of list.keys) {
        const raw = await env.USER_KV.get(key.name);
        if (raw) {
          const user = JSON.parse(raw);
          if (user.role !== 'admin') {
            users.push({ username: user.username, role: user.role });
          }
        }
      }
      return new Response(JSON.stringify({ users }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: '服务器错误' }), { status: 500 });
    }
  }

  // 重置密码为 123456
  if (url.pathname === '/api/admin/reset-password' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { username } = body;
      if (!username) {
        return new Response(JSON.stringify({ error: '缺少用户名' }), { status: 400 });
      }
      const key = `user:${username}`;
      const raw = await env.USER_KV.get(key);
      if (!raw) {
        return new Response(JSON.stringify({ error: '用户不存在' }), { status: 404 });
      }
      const user = JSON.parse(raw);
      if (user.role === 'admin') {
        return new Response(JSON.stringify({ error: '不能重置管理员密码' }), { status: 403 });
      }
      // 重置密码为 123456
      const salt = generateSalt();
      const hash = await sha512(salt + '123456');
      user.password = `${salt}:${hash}`;
      await env.USER_KV.put(key, JSON.stringify(user));
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: '服务器错误' }), { status: 500 });
    }
  }

  return new Response('Method not allowed', { status: 405 });
}

// ---------- 工具函数（与登录/注册保持一致）----------
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

async function getUserFromCookie(request, secret) {
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  if (!tokenMatch) return null;
  try {
    const { payload } = await verifyToken(tokenMatch[1], secret);
    return payload;
  } catch {
    return null;
  }
}

async function verifyToken(token, secret) {
  const encoder = new TextEncoder();
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');
  const [headerB64, payloadB64, signatureB64] = parts;
  const signature = base64UrlDecode(signatureB64);
  const data = encoder.encode(`${headerB64}.${payloadB64}`);
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
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
  while (base64.length % 4) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
