// functions/api/admin/delete-user.js
import { getUserFromCookie } from '../../_utils/auth.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  // 验证管理员权限
  const tokenPayload = await getUserFromCookie(request, env.JWT_SECRET);
  if (!tokenPayload || tokenPayload.role !== 'admin') {
    return new Response(JSON.stringify({ error: '需要管理员权限' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: '请求格式错误' }), { status: 400 });
  }

  const { username } = body;
  if (!username) {
    return new Response(JSON.stringify({ error: '缺少用户名' }), { status: 400 });
  }

  if (username === 'admin') {
    return new Response(JSON.stringify({ error: '不能删除管理员' }), { status: 403 });
  }

  const key = `user:${username}`;
  const exists = await env.USER_KV.get(key);
  if (!exists) {
    return new Response(JSON.stringify({ error: '用户不存在' }), { status: 404 });
  }

  await env.USER_KV.delete(key);

  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
}
