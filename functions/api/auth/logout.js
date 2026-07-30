// functions/api/auth/logout.js
export async function onRequestPost() {
  const headers = new Headers({
    'Content-Type': 'application/json',
    'Set-Cookie': 'token=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
  });
  return new Response(JSON.stringify({ success: true }), { headers });
}
