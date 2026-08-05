// functions/api/auth/logout.js
import { verifyToken, addToBlacklist } from '../../_utils/auth.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  if (tokenMatch) {
    try {
      const { payload } = await verifyToken(tokenMatch[1], env.JWT_SECRET);
      await addToBlacklist(env.USER_KV, tokenMatch[1], payload.exp);
    } catch (e) {}
  }

  const headers = new Headers({
    'Content-Type': 'application/json',
    'Set-Cookie': 'token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
  });

  return new Response(JSON.stringify({ success: true }), { headers });
}