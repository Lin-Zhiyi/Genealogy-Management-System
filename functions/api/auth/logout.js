// functions/api/auth/logout.js
import { verifyToken, addToBlacklist } from '../../_utils/auth.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  // 从 cookie 获取 token 并加入黑名单
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  if (tokenMatch) {
    try {
      const { payload } = await verifyToken(tokenMatch[1], env.JWT_SECRET);
      await addToBlacklist(env.USER_KV, tokenMatch[1], payload.exp);
    } catch (e) {
      // token 无效或已过期，不需要加入黑名单
    }
  }

  const headers = new Headers({
    'Content-Type': 'application/json',
    'Set-Cookie': 'token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
  });

  return new Response(JSON.stringify({ success: true }), { headers });
}
