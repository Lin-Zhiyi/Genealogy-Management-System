export async function onRequest(context) {
  try {
    const { request, env, next } = context;
    const url = new URL(request.url);

    // ----- 1. 公开页面和接口（总是放行）-----
    const publicPaths = [
      '/login.html',
      '/login',       // 无后缀的 Clean URL
      '/register.html',
      '/register',
      '/api/auth/login',
      '/api/auth/register'
    ];
    const isPublic = publicPaths.some(p => url.pathname === p || url.pathname.startsWith(p + '?'));

    // 检查用户是否已认证
    const cookie = request.headers.get('Cookie') || '';
    const tokenMatch = cookie.match(/token=([^;]+)/);
    let isAuthenticated = false;

    if (tokenMatch) {
      try {
        await verifyToken(tokenMatch[1], env.JWT_SECRET);
        isAuthenticated = true;
      } catch (e) { /* 忽略无效 token */ }
    }

    // ----- 2. 已登录用户访问登录/注册页 → 直接去主页 -----
    if (isAuthenticated && isPublic && (url.pathname.startsWith('/login') || url.pathname.startsWith('/register'))) {
      return Response.redirect(new URL('/', request.url), 302);
    }

    // 公开路径直接放行
    if (isPublic) {
      return next();
    }

    // ----- 3. 带扩展名的静态文件直接放行 -----
    if (/\.\w+$/.test(url.pathname)) {
      return next();
    }

    // ----- 4. 需要认证的请求 -----
    if (!isAuthenticated) {
      const accept = request.headers.get('Accept') || '';
      const isPageRequest = accept.includes('text/html');

      if (isPageRequest) {
        // 页面请求 → 重定向到登录页
        const redirectUrl = new URL('/login', request.url);
        // 避免嵌套：只有当原始路径不是 /login 或 /register 时才附加 redirect
        if (!url.pathname.startsWith('/login') && !url.pathname.startsWith('/register')) {
          redirectUrl.searchParams.set('redirect', url.pathname + url.search);
        }
        return new Response(null, {
          status: 302,
          headers: {
            'Location': redirectUrl.toString(),
            'Set-Cookie': 'token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
          }
        });
      } else {
        // API 请求 → 返回 401
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // 认证通过
    return next();
  } catch (err) {
    return new Response(`Middleware Error: ${err.message}`, { status: 500 });
  }
}

// ---------- JWT 验证函数 ----------
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
  if (parts.length !== 3) throw new Error('Invalid token format');

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
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
