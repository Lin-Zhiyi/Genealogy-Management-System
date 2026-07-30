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

  // 辅助函数：获取当前数据对象
  async function getCurrentData() {
    const raw = await kv.get('family-data');
    return raw ? JSON.parse(raw) : null;
  }

  // 辅助函数：保存数据对象
  async function saveData(data) {
    await kv.put('family-data', JSON.stringify(data));
  }

  // ========== GET：返回全量数据 ==========
  if (request.method === 'GET') {
    const current = await getCurrentData();
    if (current) {
      return new Response(JSON.stringify(current), { headers });
    } else {
      return new Response(JSON.stringify({ error: 'No data yet' }), { status: 404, headers });
    }
  }

  // ========== PUT：全量覆盖（保留作为备用，支持强制覆盖） ==========
  if (request.method === 'PUT') {
    try {
      const body = await request.json();
      if (!body.families || !Array.isArray(body.families)) {
        throw new Error('数据格式错误');
      }

      const current = await getCurrentData();
      const clientVersion = body._version || 0;
      const serverVersion = current ? (current._version || 0) : 0;

      // 如果不是强制覆盖，且版本落后，则拒绝
      if (clientVersion < serverVersion && !body._forceOverwrite) {
        return new Response(JSON.stringify({
          error: '版本冲突',
          latestVersion: serverVersion,
          latestData: current
        }), { status: 409, headers });
      }

      // 更新版本并保存
      body._version = Math.max(clientVersion, serverVersion) + 1;
      await saveData(body);
      return new Response(JSON.stringify({ success: true, version: body._version }), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 400, headers });
    }
  }

  // ========== PATCH：应用操作日志（增量协同） ==========
  if (request.method === 'PATCH') {
    try {
      const { baseVersion, operations } = await request.json();
      if (!Array.isArray(operations)) {
        throw new Error('operations 必须为数组');
      }

      const current = await getCurrentData();
      if (!current) {
        throw new Error('云端无数据，无法应用操作日志');
      }
      const serverVersion = current._version || 0;

      // 版本必须完全一致，否则拒绝
      if (baseVersion !== serverVersion) {
        return new Response(JSON.stringify({
          error: '版本冲突',
          latestVersion: serverVersion,
          latestData: current
        }), { status: 409, headers });
      }

      // 依次应用操作
      for (let i = 0; i < operations.length; i++) {
        const op = operations[i];
        try {
          applyOperation(current, op);
        } catch (e) {
          // 操作失败，返回失败信息和已应用的操作数量（用于前端回滚）
          return new Response(JSON.stringify({
            error: `操作${i}失败: ${e.message}`,
            appliedCount: i,
            latestVersion: serverVersion,
            latestData: current // 返回当前未完全修改的数据？
          }), { status: 409, headers });
        }
      }

      // 全部成功，递增版本
      current._version = serverVersion + 1;
      await saveData(current);

      return new Response(JSON.stringify({
        success: true,
        version: current._version
      }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 400, headers });
    }
  }

  return new Response('Method not allowed', { status: 405, headers });
}

// ----------- 操作应用函数 -----------
function applyOperation(root, op) {
  const { action, payload } = op;

  switch (action) {
    case 'addChild': {
      const { parentId, node } = payload;
      const parent = findNodeById(root, parentId);
      if (!parent) throw new Error(`父节点 ${parentId} 不存在`);
      if (!parent.children) parent.children = [];
      parent.children.push(node);
      break;
    }
    case 'deleteMember': {
      const { memberId } = payload;
      const parent = findParentNode(root, memberId);
      if (!parent) throw new Error(`要删除的成员 ${memberId} 不存在或为根节点`);
      const idx = parent.children.findIndex(c => c.id === memberId);
      if (idx === -1) throw new Error('成员不在父节点中');
      parent.children.splice(idx, 1);
      break;
    }
    case 'setAttr': {
      const { memberId, attrName, value } = payload;
      const node = findNodeById(root, memberId);
      if (!node) throw new Error(`成员 ${memberId} 不存在`);
      if (!node.attributes) node.attributes = [];
      const existing = node.attributes.find(a => a.name === attrName);
      if (existing) {
        existing.value = value;
      } else {
        node.attributes.push({ name: attrName, value });
      }
      break;
    }
    case 'setName': {
      const { memberId, newName } = payload;
      const node = findNodeById(root, memberId);
      if (!node) throw new Error(`成员 ${memberId} 不存在`);
      node.name = newName;
      break;
    }
    case 'deleteAttr': {
      const { memberId, attrName } = payload;
      const node = findNodeById(root, memberId);
      if (!node) throw new Error(`成员 ${memberId} 不存在`);
      if (node.attributes) {
        node.attributes = node.attributes.filter(a => a.name !== attrName);
      }
      break;
    }
    case 'addFamily': {
      const { family } = payload; // family 是一个完整的家族对象 { id, name, root, preface }
      root.families.push(family);
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
      const { parentId, newOrder } = payload; // newOrder 是子节点 id 数组
      const parent = findNodeById(root, parentId);
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

// ----------- 工具函数（与前端 findNodeById 逻辑一致） -----------
function findNodeById(root, id) {
  // root 可能是根节点或家族根节点
  if (root.id === id) return root;
  if (root.children) {
    for (const child of root.children) {
      const found = findNodeById(child, id);
      if (found) return found;
    }
  }
  return null;
}

function findParentNode(root, targetId) {
  if (!root.children) return null;
  for (const child of root.children) {
    if (child.id === targetId) return root;
    const found = findParentNode(child, targetId);
    if (found) return found;
  }
  return null;
}
