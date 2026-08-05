// functions/api/auth/change-password.js
import {
  verifyToken,
  verifyPassword,
  hashPassword,
  addToBlacklist
} from '../../_utils/auth.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  // 从 cookie 获取 token
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  if (!tokenMatch) {
    return new Response(JSON.stringify({ error: '未登录' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  const token = tokenMatch[1];

  // 验证 token
  let username;
  try {
    const { payload } = await verifyToken(token, env.JWT_SECRET);
    username = payload.username;
  } catch (e) {
    return new Response(JSON.stringify({ error: '令牌无效' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 解析请求体
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: '请求格式错误' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const { oldPassword, newPassword } = body;
  if (!oldPassword || !newPassword) {
    return new Response(JSON.stringify({ error: '旧密码和新密码不能为空' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  if (newPassword.length < 6) {
    return new Response(JSON.stringify({ error: '新密码至少6个字符' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 读取用户数据
  const userData = await env.USER_KV.get(`user:${username}`);
  if (!userData) {
    return new Response(JSON.stringify({ error: '用户不存在' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const user = JSON.parse(userData);

  // 验证旧密码（兼容旧格式）
  try {
    const oldValid = await verifyPassword(oldPassword, user.password);
    if (!oldValid) {
      return new Response(JSON.stringify({ error: '旧密码错误' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (e) {
    return new Response(JSON.stringify({ error: '密码验证失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 生成新密码哈希（PBKDF2）
  const newHashedPassword = await hashPassword(newPassword);
  user.password = newHashedPassword;

  // 更新密码版本号（使旧 token 失效）
  user.pwdVersion = (user.pwdVersion || 1) + 1;

  await env.USER_KV.put(`user:${username}`, JSON.stringify(user));

  // 将当前 token 加入黑名单
  try {
    const { payload } = await verifyToken(token, env.JWT_SECRET);
    await addToBlacklist(env.USER_KV, token, payload.exp || (Math.floor(Date.now() / 1000) + 86400));
  } catch (e) {
    // 黑名单添加失败不影响改密结果
  }

  return new Response(JSON.stringify({ success: true, message: '密码修改成功' }), {
    headers: {
      'Content-Type': 'application/json',
      // 清除旧 cookie，让用户重新登录
      'Set-Cookie': 'token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
    }
  });
}
