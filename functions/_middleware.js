// functions/_middleware.js
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // 1. 放行公开页面和接口
  const publicPaths = ['/login.html', '/register.html', '/api/auth/login', '/api/auth/register'];
  if (publicPaths.some(p => url.pathname.startsWith(p))) {
    return next();
  }

  // 2. 放行带扩展名的静态资源 (js, css, png, ico 等)
  if (/\.\w+$/.test(url.pathname)) {
    return next();
  }

  // 3. 其余所有路径（包括 / 和 /api/data）都需要认证
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  let valid = false;

  if (tokenMatch) {
    try {
      const { payload } = await verifyToken(tokenMatch[1], env.JWT_SECRET);
      valid = true;
    } catch (e) {
      // token 无效，继续重定向
    }
  }

  if (!valid) {
    const redirectUrl = new URL('/login.html', request.url);
    redirectUrl.searchParams.set('redirect', url.pathname + url.search);
    return Response.redirect(redirectUrl.toString(), 302);
  }

  // 认证通过，继续请求
  return next();
}

// JWT 验证函数
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
