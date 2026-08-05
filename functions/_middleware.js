// functions/_middleware.js
import { verifyToken, generateToken, isTokenBlacklisted } from './_utils/auth.js';

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
    let tokenPayload = null;
    let token = null;

    if (tokenMatch) {
      token = tokenMatch[1];
      try {
        const { payload } = await verifyToken(token, env.JWT_SECRET);
        // 检查 token 是否在黑名单中
        const blacklisted = await isTokenBlacklisted(env.USER_KV, token);
        if (blacklisted) {
          isAuthenticated = false;
        } else {
          isAuthenticated = true;
          tokenPayload = payload;
        }
      } catch (e) {
        // token 无效或已过期
        isAuthenticated = false;
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

    // ===== 滑动续期 =====
    // 如果 token 剩余时间小于 12 小时，重新签发新 token
    let response;
    if (tokenPayload) {
      const now = Math.floor(Date.now() / 1000);
      const remaining = tokenPayload.exp - now;

      if (remaining < 12 * 3600 && remaining > 0) {
        // 检查密码版本号是否一致（需要读取用户数据）
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
        } catch (e) {
          // 读取失败，默认通过（避免影响正常使用）
        }

        if (pwdVersionValid) {
          // 生成新 token
          const newToken = await generateToken(
            {
              username: tokenPayload.username,
              role: tokenPayload.role,
              pwdVersion: tokenPayload.pwdVersion || 1
            },
            env.JWT_SECRET,
            '24h'
          );

          // 继续处理请求，但在响应中设置新 cookie
          response = await next();

          // 复制响应头并添加新 cookie
          const newHeaders = new Headers(response.headers);
          newHeaders.set('Set-Cookie', `token=${newToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`);

          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: newHeaders
          });
        } else {
          // 密码版本不一致，token 已失效
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

    // 认证通过，无需续期
    return next();

  } catch (err) {
    return new Response(`Middleware Error: ${err.message}`, { status: 500 });
  }
}
