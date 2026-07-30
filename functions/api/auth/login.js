export async function onRequestPost(context) {
  const { request, env } = context;
  const { username, password } = await request.json();

  if (!username || !password) {
    return new Response(JSON.stringify({ error: '用户名和密码不能为空' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const userData = await env.USER_KV.get(`user:${username}`);
  if (!userData) {
    return new Response(JSON.stringify({ error: '用户名或密码错误' }), { status: 401 });
  }

  const user = JSON.parse(userData);
  const [salt, storedHash] = user.password.split(':');
  const hash = await sha512(salt + password);

  if (hash !== storedHash) {
    return new Response(JSON.stringify({ error: '用户名或密码错误' }), { status: 401 });
  }

  const token = await generateToken({ username, role: user.role }, env.JWT_SECRET, '24h');

  const headers = new Headers({
    'Content-Type': 'application/json',
    'Set-Cookie': `token=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
  });

  return new Response(JSON.stringify({ success: true }), { headers });
}

async function sha512(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-512', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function generateToken(payload, secret, expiresIn) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (expiresIn.endsWith('h') ? parseInt(expiresIn) * 3600 : 86400);
  const fullPayload = { ...payload, iat: now, exp };

  const encoder = new TextEncoder();
  const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const payloadB64 = btoa(JSON.stringify(fullPayload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const data = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}
