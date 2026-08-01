// functions/api/data.js
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (url.pathname !== '/api/data') {
    return new Response('Not found', { status: 404 });
  }

  const origin = request.headers.get('Origin') || '';
  const allowedOrigins = ['https://yourdomain.com', 'http://localhost:8787'];
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Methods': 'GET, PUT, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  if (allowedOrigins.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
  } else {
    headers['Access-Control-Allow-Origin'] = allowedOrigins[0];
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers });
  }

  // 获取当前用户信息（角色和用户名）
  let username, role;
  try {
    const tokenPayload = await getUserFromCookie(request, env.JWT_SECRET);
    if (!tokenPayload) {
      return new Response(JSON.stringify({ error: '未登录' }), { status: 401, headers });
    }
    username = tokenPayload.username;
    role = tokenPayload.role || 'viewer';
  } catch (e) {
    return new Response(JSON.stringify({ error: '认证失败' }), { status: 401, headers });
  }

  const kv = env.genealogy_management_system;
  if (!kv) {
    return new Response(JSON.stringify({ error: 'KV 未绑定' }), { status: 500, headers });
  }

  // 全局共享键名（所有用户共用一份族谱）
  const kvKey = 'family-data';
  const backupListKey = 'family-data-backup-list';
  const backupLastTimeKey = 'family-data-backup-lasttime';
  const BACKUP_INTERVAL_MS = 5 * 60 * 1000;

  async function getCurrentData() {
    const raw = await kv.get(kvKey);
    return raw ? JSON.parse(raw) : null;
  }

  async function saveData(data) {
    await kv.put(kvKey, JSON.stringify(data));
  }

  async function tryBackup(data, ctx) {
    const now = Date.now();
    const lastBackupStr = await kv.get(backupLastTimeKey);
    const lastBackupTime = lastBackupStr ? parseInt(lastBackupStr) : 0;
    if (now - lastBackupTime >= BACKUP_INTERVAL_MS) {
      const timestamp = now;
      const backupKey = `family-data-backup-${timestamp}`;
      await kv.put(backupKey, JSON.stringify(data));

      let list = [];
      const listRaw = await kv.get(backupListKey);
      if (listRaw) {
        list = JSON.parse(listRaw);
      }
      list.push({ key: backupKey, timestamp });
      if (list.length > 10) {
        const removed = list.splice(0, list.length - 10);
        for (const item of removed) {
          ctx.waitUntil(kv.delete(item.key));
        }
      }
      await kv.put(backupListKey, JSON.stringify(list));
      await kv.put(backupLastTimeKey, String(timestamp));
    }
  }

  // ---------- 节点查找 ----------
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

  function findMemberByName(node, name) {
    if (!node.isRoot && node.name === name) return node;
    if (node.children) {
      for (const child of node.children) {
        const found = findMemberByName(child, name);
        if (found) return found;
      }
    }
    return null;
  }

  function addDescendants(node, set) {
    if (node.children) {
      for (const child of node.children) {
        set.add(child.id);
        addDescendants(child, set);
      }
    }
  }

  // 获取编辑用户有权编辑的节点ID集合
  function getEditableNodeIds(data, username) {
    const editable = new Set();
    if (!data || !data.families) return editable;
    for (const fam of data.families) {
      const member = findMemberByName(fam.root, username);
      if (member) {
        editable.add(member.id); // 本人
        addDescendants(member, editable); // 所有后代
        const parent = findParentInTree(fam.root, member.id);
        if (parent && !parent.isRoot) {
          editable.add(parent.id);
        }
        break;
      }
    }
    return editable;
  }

  // 权限校验
  function checkPermission(data, username, role, action, payload) {
    if (role === 'admin') return true;
    if (role === 'viewer') return false;

    if (role === 'editor') {
      switch (action) {
        case 'addFamily':
        case 'deleteFamily':
        case 'renameFamily':
        case 'setFamilyPreface':
          return false;

        case 'addChild': {
          const editableIds = getEditableNodeIds(data, username);
          return editableIds.has(payload.parentId);
        }
        case 'deleteMember': {
          // 只能删除本人或直系后代，不能删除父亲
          const member = findNodeInFamilies(data, payload.memberId);
          if (!member) return false;

          // 检查是否在可编辑集合中（可编辑集合包含本人、后代、父亲）
          const editableIds = getEditableNodeIds(data, username);
          if (!editableIds.has(payload.memberId)) return false;

          // 如果是父亲节点，禁止删除（父亲是可编辑的但不可删除）
          const parent = findParentInFamilies(data, payload.memberId);
          if (parent && !parent.isRoot && parent.name === username && payload.memberId !== memberOfName(data, username)?.id) {
            return false;
          }
          // 更精确判断：查找用户本人节点，若被删除节点不是用户本人且其父节点姓名等于用户名，则不允许删除（因为那是父亲或父亲的其它子女？父亲其它子女不应该可编辑？按需求父亲只能编辑其本人和其父亲？不对，需求规定只能编辑本人、直系后代、父亲，所以父亲节点下的其他子女（即用户的兄弟姐妹）不在可编辑范围内，因此不会被包含在 editableIds 中，所以这里主要防止删除父亲本人。
          // 简化：获取用户本人节点ID，如果被删除节点ID等于父亲的ID（即父亲节点），则拒绝。
          const self = findMemberByName(data, username);
          if (self) {
            const father = findParentInFamilies(data, self.id);
            if (father && payload.memberId === father.id) {
              return false; // 不允许删除父亲
            }
          }
          return true;
        }
        case 'setAttr':
        case 'setName':
        case 'deleteAttr': {
          const editableIds = getEditableNodeIds(data, username);
          return editableIds.has(payload.memberId);
        }
        case 'reorderChildren': {
          const editableIds = getEditableNodeIds(data, username);
          return editableIds.has(payload.parentId);
        }
        default:
          return false;
      }
    }
    return false;
  }

  // 辅助：获取姓名对应的成员节点（用于删除权限判断）
  function memberOfName(data, name) {
    if (!data || !data.families) return null;
    for (const fam of data.families) {
      const found = findMemberByName(fam.root, name);
      if (found) return found;
    }
    return null;
  }

  function applyOperation(root, op, username, role) {
    const { action, payload } = op;
    if (!checkPermission(root, username, role, action, payload)) {
      throw new Error('权限不足');
    }
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
    const action = url.searchParams.get('action');

    if (action === 'list_backups') {
      if (role !== 'admin') {
        return new Response(JSON.stringify({ error: '权限不足' }), { status: 403, headers });
      }
      const listRaw = await kv.get(backupListKey);
      const list = listRaw ? JSON.parse(listRaw) : [];
      return new Response(JSON.stringify({ backups: list }), { headers });
    }

    const current = await getCurrentData();
    if (current) {
      return new Response(JSON.stringify(current), { headers });
    } else {
      return new Response(JSON.stringify({ error: 'No data yet' }), { status: 404, headers });
    }
  }

  // ========== POST：回滚备份（仅管理员） ==========
  if (request.method === 'POST' && url.searchParams.get('action') === 'restore') {
    if (role !== 'admin') {
      return new Response(JSON.stringify({ error: '权限不足' }), { status: 403, headers });
    }
    try {
      const body = await request.json();
      const backupKey = body.backupKey;
      if (!backupKey) {
        return new Response(JSON.stringify({ error: '缺少备份键' }), { status: 400, headers });
      }

      const listRaw = await kv.get(backupListKey);
      const list = listRaw ? JSON.parse(listRaw) : [];
      if (!list.some(b => b.key === backupKey)) {
        return new Response(JSON.stringify({ error: '备份不存在' }), { status: 404, headers });
      }

      const backupData = await kv.get(backupKey);
      if (!backupData) {
        return new Response(JSON.stringify({ error: '备份数据丢失' }), { status: 404, headers });
      }

      const current = await getCurrentData();
      if (current) {
        const autoBackupKey = `family-data-backup-${Date.now()}`;
        await kv.put(autoBackupKey, JSON.stringify(current));
        let list2 = [];
        const listRaw2 = await kv.get(backupListKey);
        if (listRaw2) list2 = JSON.parse(listRaw2);
        list2.push({ key: autoBackupKey, timestamp: Date.now() });
        if (list2.length > 10) list2.shift();
        await kv.put(backupListKey, JSON.stringify(list2));
      }

      await kv.put(kvKey, backupData);
      return new Response(JSON.stringify({ success: true, message: '数据已恢复' }), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 400, headers });
    }
  }

  // ========== PUT：全量覆盖（仅管理员） ==========
  if (request.method === 'PUT') {
    if (role !== 'admin') {
      return new Response(JSON.stringify({ error: '权限不足' }), { status: 403, headers });
    }
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
      context.waitUntil(tryBackup(body, context));
      return new Response(JSON.stringify({ success: true, version: body._version }), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 400, headers });
    }
  }

  // ========== PATCH：增量操作 ==========
  if (request.method === 'PATCH') {
    try {
      const { operations } = await request.json();
      if (!Array.isArray(operations)) throw new Error('operations 必须为数组');

      let current = await getCurrentData();
      if (!current) {
        current = { families: [], _version: 0 };
      }

      for (let i = 0; i < operations.length; i++) {
        const op = operations[i];
        try {
          applyOperation(current, op, username, role);
        } catch (e) {
          return new Response(JSON.stringify({
            error: `操作${i}失败: ${e.message}`,
            appliedCount: i
          }), { status: 409, headers });
        }
      }

      current._version = (current._version || 0) + 1;
      await saveData(current);
      context.waitUntil(tryBackup(current, context));

      return new Response(JSON.stringify({ success: true, version: current._version }), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 400, headers });
    }
  }

  return new Response('Method not allowed', { status: 405, headers });
}

// ---------- JWT 工具函数 ----------
async function getUserFromCookie(request, secret) {
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

async function verifyToken(token, secret) {
  const encoder = new TextEncoder();
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');

  const [headerB64, payloadB64, signatureB64] = parts;
  const signature = base64UrlDecode(signatureB64);
  const data = encoder.encode(`${headerB64}.${payloadB64}`);

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const valid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!valid) throw new Error('Signature invalid');

  const payloadBytes = base64UrlDecode(payloadB64);
  const payloadText = new TextDecoder().decode(payloadBytes);
  const payload = JSON.parse(payloadText);

  if (payload.exp && payload.exp < Date.now() / 1000) throw new Error('Token expired');
  return { payload };
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
