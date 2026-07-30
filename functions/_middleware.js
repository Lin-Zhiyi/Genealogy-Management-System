// functions/_middleware.js
export async function onRequest(context) {
  try {
    const { request, env, next } = context;
    const url = new URL(request.url);

    // ----- 1. 公开的页面和接口（总是放行）-----
    const publicPaths = ['/login.html', '/register.html', '/api/auth/login', '/api/auth/register'];
    const isPublic = publicPaths.some(p => url.pathname.startsWith(p));

    // 检查用户是否持有有效 token
    const cookie = request.headers.get('Cookie') || '';
    const tokenMatch = cookie.match(/token=([^;]+)/);
    let isAuthenticated = false;

    if (tokenMatch) {
      try {
        await verifyToken(tokenMatch[1], env.JWT_SECRET);
        isAuthenticated = true;
      } catch (e) {
        // token 无效，忽略
      }
    }

    // ----- 2. 已登录用户访问登录/注册页 → 重定向到主页 -----
    if (isAuthenticated && isPublic && (url.pathname === '/login.html' || url.pathname === '/register.html')) {
      return Response.redirect(new URL('/', request.url), 302);
    }

    // 公开路径直接放行（包括未登录访问登录/注册页、以及认证接口）
    if (isPublic) {
      return next();
    }

    // ----- 3. 带扩展名的静态资源（.js .css .png .ico 等）直接放行 -----
    if (/\.\w+$/.test(url.pathname)) {
      return next();
    }

    // ----- 4. 需要认证的请求 -----
    if (!isAuthenticated) {
      // 判断是否为页面请求（浏览器导航）
      const accept = request.headers.get('Accept') || '';
      const isPageRequest = accept.includes('text/html');

      if (isPageRequest) {
        // 页面请求 → 重定向到登录页，并清除可能无效的 Cookie
        const redirectUrl = new URL('/login.html', request.url);
        redirectUrl.searchParams.set('redirect', url.pathname + url.search);
        return new Response(null, {
          status: 302,
          headers: {
            'Location': redirectUrl.toString(),
            'Set-Cookie': 'token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
          }
        });
      } else {
        // API 请求 → 返回 401，避免 fetch 跟随重定向造成混乱
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // ----- 5. 认证通过，继续处理请求 -----
    return next();
  } catch (err) {
    return new Response(`Middleware Error: ${err.message}`, { status: 500 });
  }
}

// ---------- JWT 验证函数（与之前相同）----------
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
