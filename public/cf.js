// Cloudflare sürümü için köprü: uygulamanın kullandığı window.claude arayüzünü (db, user, downloads)
// sunucudaki /api uçlarına bağlar. Değişiklikler ~10 sn'de bir (sayfa açıkken) alınır. Giriş: kullanıcı adı + şifre.
(function () {
  'use strict';
  window.__CF = true;
  const POLL = 10000;
  let failCount = 0;

  async function call(path, data) {
    const opt = data === undefined
      ? { method: 'GET', credentials: 'same-origin', redirect: 'manual', cache: 'no-store' }
      : { method: 'POST', credentials: 'same-origin', redirect: 'manual', cache: 'no-store', headers: { 'content-type': 'application/json', 'x-tip': '1' }, body: JSON.stringify(data) };
    let r;
    try { r = await fetch('/api/' + path, opt); }
    catch (e) { throw { code: 'unavailable' }; }
    let j = null; try { j = await r.json(); } catch (e) { }
    if (!r.ok) throw { code: (j && j.error) || ('http-' + r.status), status: r.status };
    return j;
  }

  // ---------- anlık görüntü nesneleri ----------
  const frz = o => { if (o && typeof o === 'object') { Object.freeze(o); Object.values(o).forEach(frz); } return o; };
  const docSnap = (id, exists, data) => { const d = exists ? frz(data) : undefined; return { id, exists, data: () => d, metadata: { fromCache: false, hasPendingWrites: false } }; };
  const qSnap = docs => { const ds = docs.map(([id, d]) => docSnap(id, true, d)); return { docs: ds, size: ds.length, empty: !ds.length, forEach: f => ds.forEach(f), docChanges: () => [], metadata: { fromCache: false } }; };
  const toSnap = (q, v) => q.t === 'doc' ? docSnap(q.p.split('/')[1], v.exists, v.data) : qSnap(v.docs);

  // ---------- abonelikler ----------
  const subs = new Map(); let seq = 0, timer = null, busy = false, again = false, lastSession;
  function schedule(ms) { clearTimeout(timer); timer = setTimeout(sync, ms); }
  async function sync() {
    clearTimeout(timer);
    if (busy) { again = true; return; }
    if (document.visibilityState === 'hidden' && subs.size) { schedule(POLL); return; }
    busy = true;
    try {
      const list = [...subs.values()].map(s => ({ k: s.k, t: s.q.t, p: s.q.p, w: s.q.w, o: s.q.o, l: s.q.l, r: s.r }));
      if (list.length) {
        const j = await call('sync', { subs: list });
        failCount = 0;
        for (const [k, v] of Object.entries(j.out || {})) {
          const s = subs.get(k); if (!s) continue;
          if (v.e === 'permission-denied') {
            // yetkisi olmayan bölüm: sessizce boş göster (giriş yapılınca dolar)
            s.r = v.r; if (s.last === '∅') continue; s.last = '∅';
            try { s.next(toSnap(s.q, s.q.t === 'doc' ? { exists: false, data: null } : { docs: [] })); } catch (e) { console.error(e); }
            continue;
          }
          if (v.e) { s.r = v.r; if (s.err) try { s.err({ code: v.e }); } catch (e) { } continue; }
          s.r = v.r;
          const str = JSON.stringify(v.v);
          if (str === s.last) continue;
          s.last = str;
          try { s.next(toSnap(s.q, v.v)); } catch (e) { console.error(e); }
        }
        const cur = j.s || null;
        if (lastSession !== undefined && lastSession && !cur && window.__cfSessionLost) window.__cfSessionLost();
        lastSession = cur;
      }
    } catch (e) {
      failCount++;
    } finally {
      busy = false;
      const yeni = [...subs.values()].some(x => x.r === -1);
      if (again || (yeni && !failCount)) { again = false; schedule(50); } else schedule(failCount ? Math.min(60000, POLL * (failCount + 1)) : POLL);
    }
  }
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') schedule(100); });
  window.addEventListener('online', () => schedule(100));
  function subscribe(q, next, err) {
    const k = 's' + (++seq);
    subs.set(k, { k, q, next, err, r: -1, last: null });
    schedule(30);
    return () => subs.delete(k);
  }
  window.__cfResync = () => { subs.forEach(s => { s.r = -1; s.last = null; }); schedule(30); };

  // ---------- db arayüzü ----------
  function dref(path) {
    const q = { t: 'doc', p: path };
    return {
      id: path.split('/').pop(), path,
      get: async () => toSnap(q, await call('get', q)),
      set: async d => { await call('w', { ops: [{ op: 'set', p: path, d: JSON.parse(JSON.stringify(d)) }] }); schedule(150); },
      update: async d => { await call('w', { ops: [{ op: 'upd', p: path, d: JSON.parse(JSON.stringify(d)) }] }); schedule(150); },
      delete: async () => { await call('w', { ops: [{ op: 'del', p: path }] }); schedule(150); },
      onSnapshot: (n, e) => subscribe(q, n, e),
    };
  }
  function cref(coll, w, o, l) {
    const q = { t: 'q', p: coll, w: w || [], o: o || null, l: l || 0 };
    return {
      path: coll,
      where: (f, op, v) => cref(coll, (w || []).concat([[f, op, v]]), o, l),
      orderBy: (f, dir) => cref(coll, w, [f, dir || 'asc'], l),
      limit: n => cref(coll, w, o, n),
      doc: id => dref(coll + '/' + (id || (Date.now().toString(36) + Math.random().toString(36).slice(2, 10)))),
      get: async () => toSnap(q, await call('get', q)),
      onSnapshot: (n, e) => subscribe(q, n, e),
    };
  }
  const db = {
    doc: p => dref(p),
    collection: c => cref(c),
    batch: () => { const ops = []; return { set: (r, d) => { ops.push({ op: 'set', p: r.path, d: JSON.parse(JSON.stringify(d)) }); }, update: (r, d) => { ops.push({ op: 'upd', p: r.path, d }); }, delete: r => { ops.push({ op: 'del', p: r.path }); }, commit: async () => { if (ops.length) await call('w', { ops }); schedule(150); } }; },
  };

  // ---------- kullanıcı ----------
  let mePromise = null;
  const me = () => mePromise || (mePromise = call('me').catch(e => { mePromise = null; throw e; }));
  const user = {
    id: async () => null, // claude.ai hesap eşleştirmesi bu sürümde kullanılmaz; giriş kullanıcı adı/şifre ile
    isOwner: async () => !!(await me()).owner,
    me: async () => { const m = await me(); return { name: m.email }; },
    profiles: async ids => Object.fromEntries(ids.map(i => [i, { name: i }])),
  };

  // ---------- indirme ----------
  const downloads = {
    save: async ({ filename, data }) => {
      const b = data instanceof Blob ? data : new Blob([data]);
      const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = filename;
      document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
      return { status: 'saved' };
    },
  };

  // ---------- oturum uçları (uygulama içinden çağrılır) ----------
  window.__cf = {
    me,
    login: (u, p) => call('login', { u, p }),
    logout: () => call('logout', {}),
    pw: (o, n) => call('pw', { old: o, new: n }),
    importAll: docs => call('import', { docs }),
    canli: () => call('canli', {}),
    resync: () => window.__cfResync(),
  };

  window.claude = { use: async n => n === 'db' ? db : n === 'user' ? user : n === 'downloads' ? downloads : null };

  // ---------- uygulama olarak kurulum (PWA) ----------
  if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => { }));
})();
