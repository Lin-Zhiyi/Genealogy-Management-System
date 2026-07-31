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

  const kv = env.genealogy_management_system; // 你的 KV 绑定变量名
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

  // ---------- 节点查找（支持 families 结构）----------
  function findNodeInFamilies(data, id) {
    if (!data || !data.families) return null;
    for (const fam of data.families) {
      const found = findNodeInTree(fam.root, id);
      if (found) return found;
    }
    return null;
  }

  function findNodeInTree(node, id) {
    if (node.id === id) return node;
    if (node.children) {
      for (const child of node.children) {
        const found = findNodeInTree(child, id);
        if (found) return found;
      }
    }
    return null;
  }

  function findParentInFamilies(data, targetId) {
    if (!data || !data.families) return null;
    for (const fam of data.families) {
      if (fam.root.children) {
        const parent = findParentInTree(fam.root, targetId);
        if (parent) return parent;
      }
    }
    return null;
  }

  function findParentInTree(node, targetId) {
    if (!node.children) return null;
    for (const child of node.children) {
      if (child.id === targetId) return node;
      const found = findParentInTree(child, targetId);
      if (found) return found;
    }
    return null;
  }

  // ---------- 操作执行 ----------
  function applyOperation(root, op) {
    const { action, payload } = op;
    switch (action) {
      case 'addChild': {
        const { parentId, node } = payload;
        const parent = findNodeInFamilies(root, parentId) || findNodeInTree(root, parentId);
        if (!parent) throw new Error(`父节点 ${parentId} 不存在`);
        if (!parent.children) parent.children = [];
        parent.children.push(node);
        break;
      }
      case 'deleteMember': {
        const { memberId } = payload;
        const parent = findParentInFamilies(root, memberId) || findParentInTree(root, memberId);
        if (!parent) throw new Error(`要删除的成员 ${memberId} 的父节点不存在`);
        const idx = parent.children.findIndex(c => c.id === memberId);
        if (idx === -1) throw new Error('成员不在父节点中');
        parent.children.splice(idx, 1);
        break;
      }
      case 'setAttr': {
        const { memberId, attrName, value } = payload;
        const node = findNodeInFamilies(root, memberId) || findNodeInTree(root, memberId);
        if (!node) throw new Error(`成员 ${memberId} 不存在`);
        if (!node.attributes) node.attributes = [];
        const existing = node.attributes.find(a => a.name === attrName);
        if (existing) existing.value = value;
        else node.attributes.push({ name: attrName, value });
        break;
      }
      case 'setName': {
        const { memberId, newName } = payload;
        const node = findNodeInFamilies(root, memberId) || findNodeInTree(root, memberId);
        if (!node) throw new Error(`成员 ${memberId} 不存在`);
        node.name = newName;
        break;
      }
      case 'deleteAttr': {
        const { memberId, attrName } = payload;
        const node = findNodeInFamilies(root, memberId) || findNodeInTree(root, memberId);
        if (!node) throw new Error(`成员 ${memberId} 不存在`);
        if (node.attributes) node.attributes = node.attributes.filter(a => a.name !== attrName);
        break;
      }
      case 'addFamily': {
        root.families.push(payload.family);
        break;
      }
      case 'deleteFamily': {
        const { familyId } = payload;
        const idx = root.families.findIndex(f => f.id === familyId);
        if (idx === -1) throw new Error(`家族 ${familyId} 不存在`);
        root.families.splice(idx, 1);
        break;
      }
      case 'renameFamily': {
        const { familyId, newName } = payload;
        const fam = root.families.find(f => f.id === familyId);
        if (!fam) throw new Error(`家族 ${familyId} 不存在`);
        fam.name = newName;
        break;
      }
      case 'setFamilyPreface': {
        const { familyId, preface } = payload;
        const fam = root.families.find(f => f.id === familyId);
        if (!fam) throw new Error(`家族 ${familyId} 不存在`);
        fam.preface = preface;
        break;
      }
      case 'reorderChildren': {
        const { parentId, newOrder } = payload;
        const parent = findNodeInFamilies(root, parentId) || findNodeInTree(root, parentId);
        if (!parent || !parent.children) throw new Error(`父节点 ${parentId} 不存在或无子节点`);
        const reordered = [];
        for (const id of newOrder) {
          const child = parent.children.find(c => c.id === id);
          if (!child) throw new Error(`子节点 ${id} 不在父节点中`);
          reordered.push(child);
        }
        parent.children = reordered;
        break;
      }
      default:
        throw new Error(`未知操作: ${action}`);
    }
  }

  // ========== GET ==========
  if (request.method === 'GET') {
    const current = await getCurrentData();
    if (current) {
      return new Response(JSON.stringify(current), { headers });
    } else {
      return new Response(JSON.stringify({ error: 'No data yet' }), { status: 404, headers });
    }
  }

  // ========== PUT（全量覆盖，保留强制覆盖） ==========
  if (request.method === 'PUT') {
    try {
      const body = await request.json();
      if (!body.families || !Array.isArray(body.families)) throw new Error('数据格式错误');
      const current = await getCurrentData();
      const clientVersion = body._version || 0;
      const serverVersion = current ? (current._version || 0) : 0;
      if (clientVersion < serverVersion && !body._forceOverwrite) {
        return new Response(JSON.stringify({
          error: '版本冲突',
          latestVersion: serverVersion,
          latestData: current
        }), { status: 409, headers });
      }
      body._version = Math.max(clientVersion, serverVersion) + 1;
      await saveData(body);
      return new Response(JSON.stringify({ success: true, version: body._version }), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 400, headers });
    }
  }

  // ========== PATCH（无版本检查，直接应用操作） ==========
  if (request.method === 'PATCH') {
    try {
      const { operations } = await request.json(); // 不再需要 baseVersion
      if (!Array.isArray(operations)) throw new Error('operations 必须为数组');

      let current = await getCurrentData();
      if (!current) {
        current = { families: [], _version: 0 };
      }

      // 依次应用所有操作
      for (let i = 0; i < operations.length; i++) {
        const op = operations[i];
        try {
          applyOperation(current, op);
        } catch (e) {
          // 如果某个操作失败，返回错误，但之前成功的操作已经修改了 current，这可能导致不一致。
          // 简单处理：返回失败，丢弃本次所有操作。
          return new Response(JSON.stringify({
            error: `操作${i}失败: ${e.message}`,
            appliedCount: i
          }), { status: 409, headers });
        }
      }

      // 递增版本
      current._version = (current._version || 0) + 1;
      await saveData(current);

      return new Response(JSON.stringify({ success: true, version: current._version }), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 400, headers });
    }
  }

  return new Response('Method not allowed', { status: 405, headers });
}
