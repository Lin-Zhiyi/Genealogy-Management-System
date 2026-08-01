// functions/_middleware.js
export async function onRequest(context) {
  try {
    const { request, env, next } = context;
    const url = new URL(request.url);

    // 公开资源：登录/注册/认证接口
    const publicPaths = [
      '/login.html', '/login', '/register.html', '/register',
      '/api/auth/login', '/api/auth/register'
    ];
    const isPublic = publicPaths.some(p => url.pathname === p || url.pathname.startsWith(p + '/'));

    // 检查用户是否已认证
    const cookie = request.headers.get('Cookie') || '';
    const tokenMatch = cookie.match(/token=([^;]+)/);
    let isAuthenticated = false;

    if (tokenMatch) {
      try {
        await verifyToken(tokenMatch[1], env.JWT_SECRET);
        isAuthenticated = true;
      } catch (e) {
        // token 无效
      }
    }

    // 已登录用户访问登录/注册页 → 重定向到主页
    if (isAuthenticated && isPublic && (url.pathname.startsWith('/login') || url.pathname.startsWith('/register'))) {
      return Response.redirect(new URL('/', request.url), 302);
    }

    // 公开路径直接放行
    if (isPublic) {
      return next();
    }

    // admin 路径特殊处理：永远返回 JSON，绝不重定向
    if (url.pathname.startsWith('/api/admin')) {
      if (!isAuthenticated) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      // 已认证，放行给 admin.js 做进一步角色校验
      return next();
    }

    // 带扩展名的静态文件放行
    if (/\.\w+$/.test(url.pathname)) {
      return next();
    }

    // 需要认证的其他请求
    if (!isAuthenticated) {
      const accept = request.headers.get('Accept') || '';
      const isPageRequest = accept.includes('text/html');

      if (isPageRequest) {
        // 页面请求 → 重定向到登录页
        const redirectUrl = new URL('/login', request.url);
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

// ---------- JWT 验证（与 login.js 完全一致）----------
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
