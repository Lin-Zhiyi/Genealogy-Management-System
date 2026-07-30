// functions/_middleware.js
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // 白名单：允许访问登录页、注册页、静态资源、登录/注册 API
  const publicPaths = ['/login.html', '/register.html', '/api/auth/login', '/api/auth/register'];
  const isPublic = publicPaths.some(p => url.pathname.startsWith(p)) ||
                   url.pathname.startsWith('/assets/'); // 如果有静态资源目录

  if (isPublic) {
    return next();
  }

  // 获取 Cookie 中的 token
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  let valid = false;

  if (tokenMatch) {
    try {
      const { payload } = await verifyToken(tokenMatch[1], env.JWT_SECRET);
      valid = true;
    } catch (e) {
      // token 无效
    }
  }

  if (!valid) {
    // 重定向到登录页，保留原始路径用于登录后跳转
    const redirectUrl = new URL('/login.html', request.url);
    redirectUrl.searchParams.set('redirect', url.pathname + url.search);
    return Response.redirect(redirectUrl.toString(), 302);
  }

  // 认证通过，继续处理请求
  return next();
}

// JWT 验证函数（使用 Web Crypto API）
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
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(base64url.length + (4 - base64url.length % 4) % 4, '=');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
