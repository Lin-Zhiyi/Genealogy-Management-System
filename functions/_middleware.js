// functions/_middleware.js
import { verifyToken, generateToken, isTokenBlacklisted } from './_utils/auth.js';

export async function onRequest(context) {
  try {
    const { request, env, next } = context;
    const url = new URL(request.url);

    const publicPaths = [
      '/login.html', '/login', '/register.html', '/register',
      '/api/auth/login', '/api/auth/register'
    ];
    const isPublic = publicPaths.some(p => url.pathname === p || url.pathname.startsWith(p + '/'));

    const cookie = request.headers.get('Cookie') || '';
    const tokenMatch = cookie.match(/token=([^;]+)/);
    let isAuthenticated = false;
    let tokenPayload = null;
    let token = null;

    if (tokenMatch) {
      token = tokenMatch[1];
      try {
        const { payload } = await verifyToken(token, env.JWT_SECRET);
        const blacklisted = await isTokenBlacklisted(env.USER_KV, token);
        if (blacklisted) {
          isAuthenticated = false;
        } else {
          isAuthenticated = true;
          tokenPayload = payload;
        }
      } catch (e) {
        isAuthenticated = false;
      }
    }

    if (isAuthenticated && isPublic && (url.pathname.startsWith('/login') || url.pathname.startsWith('/register'))) {
      return Response.redirect(new URL('/', request.url), 302);
    }

    if (isPublic) {
      return next();
    }

    if (url.pathname.startsWith('/api/admin')) {
      if (!isAuthenticated) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      return next();
    }

    if (/\.\w+$/.test(url.pathname)) {
      return next();
    }

    if (!isAuthenticated) {
      const accept = request.headers.get('Accept') || '';
      const isPageRequest = accept.includes('text/html');

      if (isPageRequest) {
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
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    let response;
    if (tokenPayload) {
      const now = Math.floor(Date.now() / 1000);
      const remaining = tokenPayload.exp - now;

      if (remaining < 12 * 3600 && remaining > 0) {
        let pwdVersionValid = true;
        try {
          const userData = await env.USER_KV.get(`user:${tokenPayload.username}`);
          if (userData) {
            const user = JSON.parse(userData);
            const currentPwdVersion = user.pwdVersion || 1;
            const tokenPwdVersion = tokenPayload.pwdVersion || 1;
            if (currentPwdVersion !== tokenPwdVersion) {
              pwdVersionValid = false;
            }
          }
        } catch (e) {}

        if (pwdVersionValid) {
          const newToken = await generateToken(
            {
              username: tokenPayload.username,
              role: tokenPayload.role,
              pwdVersion: tokenPayload.pwdVersion || 1
            },
            env.JWT_SECRET,
            '24h'
          );

          response = await next();

          const newHeaders = new Headers(response.headers);
          newHeaders.set('Set-Cookie', `token=${newToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`);

          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: newHeaders
          });
        } else {
          const accept = request.headers.get('Accept') || '';
          const isPageRequest = accept.includes('text/html');

          if (isPageRequest) {
            const redirectUrl = new URL('/login', request.url);
            return new Response(null, {
              status: 302,
              headers: {
                'Location': redirectUrl.toString(),
                'Set-Cookie': 'token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
              }
            });
          } else {
            return new Response(JSON.stringify({ error: '登录已过期，请重新登录' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' }
            });
          }
        }
      }
    }

    return next();

  } catch (err) {
    return new Response(`Middleware Error: ${err.message}`, { status: 500 });
  }
}