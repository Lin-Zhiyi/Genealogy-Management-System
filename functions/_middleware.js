export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // 公开资源：登录、注册、认证接口
  const publicPaths = ['/login.html', '/register.html', '/api/auth/login', '/api/auth/register'];
  if (publicPaths.some(p => url.pathname.startsWith(p))) {
    return next();
  }

  // 带扩展名的静态文件（.html 等也放行，确保 login.html 内的资源可用）
  if (/\.\w+$/.test(url.pathname)) {
    return next();
  }

  // 其余请求（包括 /、/api/data 等）需要认证
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  let valid = false;

  if (tokenMatch) {
    try {
      await verifyToken(tokenMatch[1], env.JWT_SECRET);
      valid = true;
    } catch (e) {
      // 令牌无效，忽略
    }
  }

  if (!valid) {
    const redirectUrl = new URL('/login.html', request.url);
    redirectUrl.searchParams.set('redirect', url.pathname + url.search);
    // 清除客户端可能残留的无效 Cookie
    const response = Response.redirect(redirectUrl.toString(), 302);
    response.headers.set('Set-Cookie', 'token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
    return response;
  }

  return next();
}

// JWT 验证（使用 Web Crypto API）
async function verifyToken(token, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');

  const [headerB64, payloadB64, signatureB64] = parts;
  const signature = base64UrlToArrayBuffer(signatureB64);
  const data = encoder.encode(`${headerB64}.${payloadB64}`);

  const valid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!valid) throw new Error('Signature invalid');

  const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
  if (payload.exp && payload.exp < Date.now() / 1000) throw new Error('Token expired');

  return { payload };
}

function base64UrlToArrayBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
    .padEnd(base64url.length + (4 - base64url.length % 4) % 4, '=');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
