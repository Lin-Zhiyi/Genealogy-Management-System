// functions/api/admin/[[path]].js
import {
  getUserFromCookie,
  hashPassword,
  verifyToken
} from '../../_utils/auth.js';

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const tokenPayload = await getUserFromCookie(request, env.JWT_SECRET);
  if (!tokenPayload || tokenPayload.role !== 'admin') {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (url.pathname === '/api/admin/users' && request.method === 'GET') {
    try {
      const list = await env.USER_KV.list({ prefix: 'user:' });
      const users = [];
      for (const key of list.keys) {
        const raw = await env.USER_KV.get(key.name);
        if (raw) {
          const user = JSON.parse(raw);
          if (user.role !== 'admin') {
            users.push({ username: user.username, role: user.role });
          }
        }
      }
      return new Response(JSON.stringify({ users }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: '服务器错误' }), { status: 500 });
    }
  }

  if (url.pathname === '/api/admin/reset-password' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { username } = body;
      if (!username) {
        return new Response(JSON.stringify({ error: '缺少用户名' }), { status: 400 });
      }

      const key = `user:${username}`;
      const raw = await env.USER_KV.get(key);
      if (!raw) {
        return new Response(JSON.stringify({ error: '用户不存在' }), { status: 404 });
      }

      const user = JSON.parse(raw);
      if (user.role === 'admin') {
        return new Response(JSON.stringify({ error: '不能重置管理员密码' }), { status: 403 });
      }

      const newPassword = '123456';
      user.password = await hashPassword(newPassword);
      user.pwdVersion = (user.pwdVersion || 1) + 1;
      user.mustChangePassword = true;

      await env.USER_KV.put(key, JSON.stringify(user));

      return new Response(JSON.stringify({ success: true, message: '密码已重置为 123456，请尽快修改' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: '服务器错误' }), { status: 500 });
    }
  }

  return new Response('Method not allowed', { status: 405 });
}