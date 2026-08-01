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

  // ---------- 节点查找（限制在指定家族内）----------
  function findNodeInFamily(family, id) {
    if (!family || !family.root) return null;
    return findNodeInTree(family.root, id);
  }

  function findParentInFamily(family, targetId) {
    if (!family || !family.root) return null;
    return findParentInTree(family.root, targetId);
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

  function findParentInTree(node, targetId) {
    if (!node.children) return null;
    for (const child of node.children) {
      if (child.id === targetId) return node;
      const found = findParentInTree(child, targetId);
      if (found) return found;
    }
    return null;
  }

  // 在全量数据中查找成员（用于权限校验和获取可编辑节点集合等）
  function findMemberByName(data, name) {
    if (!data || !data.families) return null;
    for (const fam of data.families) {
      const found = findMemberInTree(fam.root, name);
      if (found) return found;
    }
    return null;
  }

  function findMemberInTree(node, name) {
    if (!node.isRoot && node.name === name) return node;
    if (node.children) {
      for (const child of node.children) {
        const found = findMemberInTree(child, name);
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

  // 获取编辑用户有权编辑的节点ID集合（遍历所有家族，但返回所有家族内的可编辑节点）
  function getEditableNodeIds(data, username) {
    const editable = new Set();
    if (!data || !data.families) return editable;
    for (const fam of data.families) {
      const member = findMemberInTree(fam.root, username);
      if (member) {
        editable.add(member.id);
        addDescendants(member, editable);
        const parent = findParentInTree(fam.root, member.id);
        if (parent && !parent.isRoot) {
          editable.add(parent.id);
        }
        // 注意：一个用户可能存在于多个家族，我们只取第一个匹配的
        // 实际使用中，编辑用户的权限应限定在当前操作的家族内，
        // 这里返回全局可编辑节点仅用于初步判断，后面在具体操作时会限制在家族内。
        break;
      }
    }
    return editable;
  }

  // 权限校验（根据操作类型和 payload 判断）
  function checkPermission(data, username, role, action, payload) {
    if (role === 'admin') return true;
    if (role === 'viewer') return false;

    if (role === 'editor') {
      // 管理员才能做家族级别的操作
      if (['addFamily', 'deleteFamily', 'renameFamily', 'setFamilyPreface'].includes(action)) {
        return false;
      }

      // 对于需要 familyId 的操作，获取该家族内用户的可编辑节点
      if (payload.familyId) {
        const family = data.families.find(f => f.id === payload.familyId);
        if (!family) return false;
        // 找到用户在该家族内的本人节点
        const self = findMemberInTree(family.root, username);
        if (!self) return false;
        const editableIds = new Set();
        editableIds.add(self.id);
        addDescendants(self, editableIds);
        const parent = findParentInTree(family.root, self.id);
        if (parent && !parent.isRoot) {
          editableIds.add(parent.id);
        }

        switch (action) {
          case 'addChild':
          case 'reorderChildren':
            return editableIds.has(payload.parentId);
          case 'deleteMember': {
            if (!editableIds.has(payload.memberId)) return false;
            // 禁止删除自己的父亲
            const father = findParentInTree(family.root, self.id);
            if (father && payload.memberId === father.id) return false;
            return true;
          }
          case 'setAttr':
          case 'setName':
          case 'deleteAttr':
            return editableIds.has(payload.memberId);
          default:
            return false;
        }
      }
      // 没有 familyId 的 editor 操作一律拒绝（例如家族级别）
      return false;
    }
    return false;
  }

  // ---------- 应用单个操作（在数据对象上，已剥离版本号）----------
  function applyOperation(rootData, op, username, role) {
    const { action, payload } = op;

    // 权限校验
    if (!checkPermission(rootData, username, role, action, payload)) {
      throw new Error('权限不足');
    }

    switch (action) {
      case 'addChild': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const parent = findNodeInFamily(family, payload.parentId);
        if (!parent) throw new Error(`父节点 ${payload.parentId} 不存在`);
        if (!parent.children) parent.children = [];
        parent.children.push(payload.node);
        break;
      }
      case 'deleteMember': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const parent = findParentInFamily(family, payload.memberId);
        if (!parent) throw new Error(`要删除的成员 ${payload.memberId} 的父节点不存在`);
        const idx = parent.children.findIndex(c => c.id === payload.memberId);
        if (idx === -1) throw new Error('成员不在父节点中');
        parent.children.splice(idx, 1);
        break;
      }
      case 'setAttr': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const node = findNodeInFamily(family, payload.memberId);
        if (!node) throw new Error(`成员 ${payload.memberId} 不存在`);
        if (!node.attributes) node.attributes = [];
        const existing = node.attributes.find(a => a.name === payload.attrName);
        if (existing) existing.value = payload.value;
        else node.attributes.push({ name: payload.attrName, value: payload.value });
        break;
      }
      case 'setName': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const node = findNodeInFamily(family, payload.memberId);
        if (!node) throw new Error(`成员 ${payload.memberId} 不存在`);
        node.name = payload.newName;
        break;
      }
      case 'deleteAttr': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const node = findNodeInFamily(family, payload.memberId);
        if (!node) throw new Error(`成员 ${payload.memberId} 不存在`);
        if (node.attributes) {
          node.attributes = node.attributes.filter(a => a.name !== payload.attrName);
        }
        break;
      }
      case 'addFamily': {
        rootData.families.push(payload.family);
        break;
      }
      case 'deleteFamily': {
        const idx = rootData.families.findIndex(f => f.id === payload.familyId);
        if (idx === -1) throw new Error(`家族 ${payload.familyId} 不存在`);
        rootData.families.splice(idx, 1);
        break;
      }
      case 'renameFamily': {
        const fam = rootData.families.find(f => f.id === payload.familyId);
        if (!fam) throw new Error(`家族 ${payload.familyId} 不存在`);
        fam.name = payload.newName;
        break;
      }
      case 'setFamilyPreface': {
        const fam = rootData.families.find(f => f.id === payload.familyId);
        if (!fam) throw new Error(`家族 ${payload.familyId} 不存在`);
        fam.preface = payload.preface;
        break;
      }
      case 'reorderChildren': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const parent = findNodeInFamily(family, payload.parentId);
        if (!parent || !parent.children) throw new Error(`父节点 ${payload.parentId} 不存在或无子节点`);
        const reordered = [];
        for (const id of payload.newOrder) {
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

  // ========== PATCH：增量操作（事务性执行） ==========
  if (request.method === 'PATCH') {
    try {
      const { operations } = await request.json();
      if (!Array.isArray(operations)) throw new Error('operations 必须为数组');

      let current = await getCurrentData();
      if (!current) {
        current = { families: [], _version: 0 };
      }

      // 1. 深拷贝当前数据，在副本上依次应用所有操作
      const tempData = JSON.parse(JSON.stringify(current));

      for (const op of operations) {
        applyOperation(tempData, op, username, role);
      }

      // 2. 全部成功，则更新版本并保存
      tempData._version = (current._version || 0) + 1;
      await saveData(tempData);
      context.waitUntil(tryBackup(tempData, context));

      return new Response(JSON.stringify({ success: true, version: tempData._version }), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 409, headers });
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
