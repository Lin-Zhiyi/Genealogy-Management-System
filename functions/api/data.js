// functions/api/data.js
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (url.pathname !== '/api/data') {
    return new Response('Not found', { status: 404 });
  }

  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, PUT, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers });
  }

  const kv = env.genealogy_management_system; // 替换为你的绑定变量名
  if (!kv) {
    return new Response(JSON.stringify({ error: 'KV 未绑定' }), { status: 500, headers });
  }

  async function getCurrentData() {
    const raw = await kv.get('family-data');
    return raw ? JSON.parse(raw) : null;
  }

  async function saveData(data) {
    await kv.put('family-data', JSON.stringify(data));
  }

  // 查找节点等辅助函数与之前相同，省略

  // ========== GET ==========
  if (request.method === 'GET') {
    const current = await getCurrentData();
    return current
      ? new Response(JSON.stringify(current), { headers })
      : new Response(JSON.stringify({ error: 'No data yet' }), { status: 404, headers });
  }

  // ========== PUT（保留，用于导入/强制覆盖） ==========
  if (request.method === 'PUT') {
    // 与之前完全相同，略
  }

  // ========== PATCH ==========
  if (request.method === 'PATCH') {
    try {
      const { baseVersion, operations } = await request.json();
      if (!Array.isArray(operations)) throw new Error('operations 必须为数组');

      let current = await getCurrentData();
      if (!current) {
        current = { families: [], _version: 0 };
      }
      const serverVersion = current._version || 0;

      if (baseVersion !== serverVersion) {
        return new Response(JSON.stringify({
          error: '版本冲突',
          latestVersion: serverVersion,
          latestData: current
        }), { status: 409, headers });
      }

      // 依次应用操作
      for (let i = 0; i < operations.length; i++) {
        try {
          applyOperation(current, operations[i]); // applyOperation 实现与之前相同
        } catch (e) {
          return new Response(JSON.stringify({
            error: `操作${i}失败: ${e.message}`,
            appliedCount: i
          }), { status: 409, headers });
        }
      }

      current._version = serverVersion + 1;
      await saveData(current);
      return new Response(JSON.stringify({ success: true, version: current._version }), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 400, headers });
    }
  }

  return new Response('Method not allowed', { status: 405, headers });
}
