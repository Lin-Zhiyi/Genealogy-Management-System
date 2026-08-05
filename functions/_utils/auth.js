// functions/_utils/auth.js
export async function generateToken(payload, secret, expiresIn = '24h') {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const expSeconds = expiresIn.endsWith('h') ? parseInt(expiresIn) * 3600 :
                     expiresIn.endsWith('d') ? parseInt(expiresIn) * 86400 : 86400;
  const fullPayload = { ...payload, iat: now, exp: now + expSeconds };
  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(fullPayload)));
  const data = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

export async function verifyToken(token, secret) {
  const encoder = new TextEncoder();
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');
  const [headerB64, payloadB64, signatureB64] = parts;
  const signature = base64UrlDecode(signatureB64);
  const data = encoder.encode(`${headerB64}.${payloadB64}`);
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!valid) throw new Error('Signature invalid');
  const payloadBytes = base64UrlDecode(payloadB64);
  const payloadText = new TextDecoder().decode(payloadBytes);
  const payload = JSON.parse(payloadText);
  if (payload.exp && payload.exp < Date.now() / 1000) throw new Error('Token expired');
  return { payload };
}

export async function getUserFromCookie(request, secret) {
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/token=([^;]+)/);
  if (!tokenMatch) return null;
  try {
    const { payload } = await verifyToken(tokenMatch[1], secret);
    return payload;
  } catch {
    return null;
  }
}

export async function hashPassword(password, salt) {
  if (!salt) salt = generateSalt();
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password),
    'PBKDF2', false, ['deriveBits']
  );
  const saltBuffer = encoder.encode(salt);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );
  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return `pbkdf2:${salt}:${hashHex}`;
}

export async function verifyPassword(password, storedPassword) {
  const parts = storedPassword.split(':');
  if (parts.length === 2) {
    const [salt, storedHash] = parts;
    const legacyHash = await sha512(salt + password);
    return legacyHash === storedHash;
  }
  if (parts.length === 3 && parts[0] === 'pbkdf2') {
    const [, salt, storedHash] = parts;
    const newHash = await hashPassword(password, salt);
    const newHashParts = newHash.split(':');
    return newHashParts[2] === storedHash;
  }
  throw new Error('密码格式错误');
}

export function generateSalt() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function sha512(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-512', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function generateCsrfToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function verifyCsrfToken(request, expectedToken) {
  const token = request.headers.get('X-CSRF-Token') || '';
  return token === expectedToken && token.length > 0;
}

export async function checkRateLimit(kv, key, maxRequests, windowMs) {
  const now = Date.now();
  const windowKey = `${key}:${Math.floor(now / windowMs)}`;
  const current = await kv.get(windowKey, { type: 'text' });
  const count = current ? parseInt(current) : 0;
  if (count >= maxRequests) {
    return { allowed: false, remaining: 0 };
  }
  await kv.put(windowKey, String(count + 1), { expirationTtl: Math.ceil(windowMs / 1000) + 60 });
  return { allowed: true, remaining: maxRequests - count - 1 };
}

export async function addToBlacklist(kv, token, expSeconds) {
  const tokenHash = await sha256(token);
  const ttl = Math.max(60, expSeconds - Math.floor(Date.now() / 1000));
  await kv.put(`blacklist:${tokenHash}`, '1', { expirationTtl: ttl });
}

export async function isTokenBlacklisted(kv, token) {
  const tokenHash = await sha256(token);
  const result = await kv.get(`blacklist:${tokenHash}`, { type: 'text' });
  return !!result;
}

async function sha256(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function base64UrlEncode(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}