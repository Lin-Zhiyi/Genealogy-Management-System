// functions/api/data.js
export async function onRequest(context) {
  const { request, env } = context;
  
  try {
    const headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': 'https://linshizupu.pages.dev',
      'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers });
    }

    // 使用你绑定好的变量名
    const kv = env.genealogy_management_system;
    if (!kv) {
      throw new Error('KV 绑定失败：genealogy_management_system 未定义');
    }

    if (request.method === 'GET') {
      const data = await kv.get('family-data');
      if (data) {
        return new Response(data, { headers });
      } else {
        return new Response(JSON.stringify({ error: 'No data yet' }), { status: 404, headers });
      }
    }

    if (request.method === 'PUT') {
      const json = await request.text();
      try {
        JSON.parse(json);
      } catch {
        return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400, headers });
      }
      await kv.put('family-data', json);
      return new Response(JSON.stringify({ success: true }), { headers });
    }

    return new Response('Method not allowed', { status: 405, headers });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': 'https://linshizupu.pages.dev',
      }
    });
  }
}
