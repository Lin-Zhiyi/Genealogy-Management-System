export async function onRequest(context) {
  try {
    const { request, env, next } = context;
    const url = new URL(request.url);

    // 公开资源：登录/注册/认证接口
    const publicPaths = ['/login.html', '/register.html', '/api/auth/login', '/api/auth/register'];
    if (publicPaths.some(p => url.pathname.startsWith(p))) {
      return next();
    }

    // 带扩展名的静态文件（包含 .html 等）
    if (/\.\w+$/.test(url.pathname)) {
      return next();
    }

    // 认证检查
    const cookie = request.headers.get('Cookie') || '';
    const tokenMatch = cookie.match(/token=([^;]+)/);
    let valid = false;
    let errorReason = '';

    if (tokenMatch) {
      try {
        await verifyToken(tokenMatch[1], env.JWT_SECRET);
        valid = true;
      } catch (e) {
        errorReason = e.message;
      }
    }

    if (!valid) {
      const redirectUrl = new URL('/login.html', request.url);
      redirectUrl.searchParams.set('redirect', url.pathname + url.search);

      // 若携带了无效 token，显示错误原因（方便排查）
      if (tokenMatch) {
        redirectUrl.searchParams.set('error', errorReason || 'invalid_token');
      }

      return new Response(null, {
        status: 302,
        headers: {
          'Location': redirectUrl.toString(),
          // 清除无效的 Cookie
          'Set-Cookie': 'token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
        }
      });
    }

    return next();
  } catch (err) {
    return new Response(`Middleware Error: ${err.message}`, { status: 500 });
  }
}

// JWT 验证（Web Crypto API）
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

  const isValid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!isValid) throw new Error('Signature invalid');

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
