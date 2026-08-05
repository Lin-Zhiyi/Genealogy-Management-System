// functions/api/auth/me.js
import { verifyToken, generateToken } from '../../_utils/auth.js';

export async function onRequestGet(context) {
  const { request, env } = context;

  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  if (!tokenMatch) {
    return new Response(JSON.stringify({ error: '未登录' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  const token = tokenMatch[1];
  try {
    const { payload } = await verifyToken(token, env.JWT_SECRET);

    const now = Math.floor(Date.now() / 1000);
    const remaining = payload.exp - now;
    const headers = { 'Content-Type': 'application/json; charset=utf-8' };

    if (remaining < 12 * 3600 && remaining > 0) {
      const newToken = await generateToken(
        { username: payload.username, role: payload.role, pwdVersion: payload.pwdVersion || 1 },
        env.JWT_SECRET,
        '24h'
      );
      headers['Set-Cookie'] = `token=${newToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`;
    }

    return new Response(
      JSON.stringify({ username: payload.username, role: payload.role }),
      { headers }
    );
  } catch (e) {
    return new Response(JSON.stringify({ error: '令牌无效' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }
}