// functions/api/data.js
import { getUserFromCookie } from '../_utils/auth.js';

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (url.pathname !== '/api/data') {
    return new Response('Not found', { status: 404 });
  }

  // CORS 头
  const origin = request.headers.get('Origin') || '';
  const allowedOrigins = ['https://yourdomain.com', 'http://localhost:8787'];
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Methods': 'GET, PUT, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
  };
  if (allowedOrigins.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
  } else if (origin) {
    headers['Access-Control-Allow-Origin'] = 'null';
  }
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers });
  }

  // 获取当前用户
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

  // KV 绑定检查
  const kv = env.genealogy_management_system;
  if (!kv) {
    console.error('KV 绑定 "genealogy_management_system" 未配置');
    return new Response(JSON.stringify({ error: '服务器配置错误' }), { status: 500, headers });
  }

  const kvKey = 'family-data';
  const backupListKey = 'family-data-backup-list';
  const backupLastTimeKey = 'family-data-backup-lasttime';
  const BACKUP_INTERVAL_MS = 5 * 60 * 1000;

  // ---------- 数据读取 ----------
  async function getCurrentData() {
    try {
      const raw = await kv.get(kvKey);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch (e) {
      console.error('getCurrentData 解析失败:', e);
      throw new Error('数据解析失败');
    }
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
      if (listRaw) list = JSON.parse(listRaw);
      list.push({ key: backupKey, timestamp });
      if (list.length > 10) {
        const removed = list.splice(0, list.length - 10);
        for (const item of removed) ctx.waitUntil(kv.delete(item.key));
      }
      await kv.put(backupListKey, JSON.stringify(list));
      await kv.put(backupLastTimeKey, String(timestamp));
    }
  }

  // ---------- 节点查找 ----------
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

  // ---------- 权限校验 ----------
  function checkPermission(data, username, role, action, payload) {
    if (role === 'admin') return true;
    if (role === 'viewer') return false;
    if (role === 'editor') {
      if (['addFamily', 'deleteFamily', 'renameFamily', 'setFamilyPreface'].includes(action)) {
        return false;
      }
      if (payload.familyId) {
        const family = data.families.find(f => f.id === payload.familyId);
        if (!family) return false;
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
      return false;
    }
    return false;
  }

  // ---------- 应用操作 ----------
  function applyOperation(rootData, op, username, role) {
    const { action, payload } = op;
    if (!checkPermission(rootData, username, role, action, payload)) {
      throw new Error('权限不足');
    }
    switch (action) {
      case 'addChild': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const parent = findNodeInFamily(family, payload.parentId);
        if (!parent) throw new Error('父节点不存在');
        if (!parent.children) parent.children = [];
        parent.children.push(payload.node);
        break;
      }
      case 'deleteMember': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const parent = findParentInFamily(family, payload.memberId);
        if (!parent) throw new Error('要删除的成员的父节点不存在');
        const idx = parent.children.findIndex(c => c.id === payload.memberId);
        if (idx === -1) throw new Error('成员不在父节点中');
        parent.children.splice(idx, 1);
        break;
      }
      case 'setAttr': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const node = findNodeInFamily(family, payload.memberId);
        if (!node) throw new Error('成员不存在');
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
        if (!node) throw new Error('成员不存在');
        node.name = payload.newName;
        break;
      }
      case 'deleteAttr': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const node = findNodeInFamily(family, payload.memberId);
        if (!node) throw new Error('成员不存在');
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
        if (idx === -1) throw new Error('家族不存在');
        rootData.families.splice(idx, 1);
        break;
      }
      case 'renameFamily': {
        const fam = rootData.families.find(f => f.id === payload.familyId);
        if (!fam) throw new Error('家族不存在');
        fam.name = payload.newName;
        break;
      }
      case 'setFamilyPreface': {
        const fam = rootData.families.find(f => f.id === payload.familyId);
        if (!fam) throw new Error('家族不存在');
        fam.preface = payload.preface;
        break;
      }
      case 'reorderChildren': {
        const family = rootData.families.find(f => f.id === payload.familyId);
        if (!family) throw new Error('家族不存在');
        const parent = findNodeInFamily(family, payload.parentId);
        if (!parent || !parent.children) throw new Error('父节点不存在或无子节点');
        const reordered = [];
        for (const id of payload.newOrder) {
          const child = parent.children.find(c => c.id === id);
          if (!child) throw new Error('子节点不在父节点中');
          reordered.push(child);
        }
        parent.children = reordered;
        break;
      }
      default:
        throw new Error('未知操作');
    }
  }

  // ========== GET ==========
  if (request.method === 'GET') {
    const action = url.searchParams.get('action');

    if (action === 'list_backups') {
      if (role !== 'admin') {
        return new Response(JSON.stringify({ error: '权限不足' }), { status: 403, headers });
      }
      try {
        const listRaw = await kv.get(backupListKey);
        const list = listRaw ? JSON.parse(listRaw) : [];
        return new Response(JSON.stringify({ backups: list }), { headers });
      } catch (e) {
        console.error('list_backups 错误:', e);
        return new Response(JSON.stringify({ error: '获取备份列表失败' }), { status: 500, headers });
      }
    }

    if (action === 'version') {
      try {
        const current = await getCurrentData();
        const version = current ? current._version || 0 : 0;
        return new Response(JSON.stringify({ version }), { headers });
      } catch (e) {
        console.error('version 错误:', e);
        return new Response(JSON.stringify({ error: '读取版本失败' }), { status: 500, headers });
      }
    }

    try {
      const current = await getCurrentData();
      if (current) {
        return new Response(JSON.stringify(current), { headers });
      } else {
        return new Response(JSON.stringify({ error: '暂无数据' }), { status: 404, headers });
      }
    } catch (e) {
      console.error('GET /api/data 错误:', e);
      return new Response(JSON.stringify({ error: '数据读取失败，请检查 KV 数据完整性' }), { status: 500, headers });
    }
  }

  // ========== POST 恢复 ==========
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
      console.log(`管理员 ${username} 恢复了备份: ${backupKey}`);
      return new Response(JSON.stringify({ success: true, message: '数据已恢复' }), { headers });
    } catch (err) {
      console.error('restore 错误:', err);
      return new Response(JSON.stringify({ error: '恢复失败' }), { status: 400, headers });
    }
  }

  // ========== PUT ==========
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
      console.log(`管理员 ${username} 全量覆盖数据，新版本: ${body._version}`);
      return new Response(JSON.stringify({ success: true, version: body._version }), { headers });
    } catch (err) {
      console.error('PUT 错误:', err);
      return new Response(JSON.stringify({ error: '保存失败' }), { status: 400, headers });
    }
  }

  // ========== PATCH ==========
  if (request.method === 'PATCH') {
    try {
      const body = await request.json();
      const { operations, baseVersion } = body;
      if (!Array.isArray(operations)) throw new Error('operations 必须为数组');
      if (typeof baseVersion !== 'number') {
        throw new Error('缺少 baseVersion 参数');
      }

      let current = await getCurrentData();
      if (!current) {
        current = { families: [], _version: 0 };
      }
      const serverVersion = current._version || 0;

      if (baseVersion !== serverVersion) {
        console.warn(`版本冲突: 客户端 ${baseVersion}, 服务端 ${serverVersion}, 用户 ${username}`);
        return new Response(JSON.stringify({
          error: '版本冲突，请刷新重试',
          latestVersion: serverVersion,
          latestData: current
        }), { status: 409, headers });
      }

      const tempData = JSON.parse(JSON.stringify(current));
      for (const op of operations) {
        applyOperation(tempData, op, username, role);
      }

      tempData._version = serverVersion + 1;
      await saveData(tempData);
      context.waitUntil(tryBackup(tempData, context));

      console.log(`PATCH 成功: 用户 ${username}, 操作数 ${operations.length}, 新版本 ${tempData._version}`);
      return new Response(JSON.stringify({ success: true, version: tempData._version }), { headers });
    } catch (err) {
      const message = err.message === '权限不足' ? '权限不足' :
                      err.message === '未知操作' ? '未知操作' :
                      '操作失败';
      console.error('PATCH 错误:', err);
      return new Response(JSON.stringify({ error: message }), { status: 409, headers });
    }
  }

  return new Response('Method not allowed', { status: 405, headers });
}