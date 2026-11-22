// Taş İşleri Personel ve Mesai Takip Programı — Cloudflare Worker
// Görevleri: kullanıcı adı/şifre ile giriş, yetki kontrolü, veritabanı (D1), saatlik hava/kur ve 15 dakikalık trafik güncellemesi.
// Veriler tek tabloda "koleksiyon/kimlik" yoluyla JSON olarak tutulur.

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS docs (path TEXT PRIMARY KEY, coll TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS docs_coll ON docs(coll)`,
  `CREATE INDEX IF NOT EXISTS docs_log_ts ON docs(coll, json_extract(data,'$.ts'))`,
  `CREATE TABLE IF NOT EXISTS meta (coll TEXT PRIMARY KEY, rev INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS oturum (token TEXT PRIMARY KEY, u TEXT NOT NULL, emp TEXT, t TEXT NOT NULL, ip TEXT, created INTEGER NOT NULL, last INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS deneme (k TEXT NOT NULL, ts INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS deneme_k ON deneme(k, ts)`,
];
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  await env.DB.batch(SCHEMA.map(s => env.DB.prepare(s)));
  schemaReady = true;
}

// ---------- yetki seviyeleri ----------
// 0 = giriş yapılmamış · 2 = çalışan / usta başı / sınırlı yönetici · 3 = yönetici
// [okuma, yazma] — listede olmayan koleksiyonlar DEF kuralını kullanır
const DEF = [2, 3];
const RULES = {
  ayarlar: [0, 3],                       // program adı ve renkleri giriş ekranında da gerekir
  ucretler: [3, 3], kayitlar: [3, 3], hareketler: [3, 3], sirket: [3, 3], odeme: [3, 3], islemlog: [3, 3],
  girisler: [3, 3], hesaplar: [9, 9],    // hesaplar: yalnız hesap yetkisi olan yöneticiler (aşağıda)
  yoklama: [2, 2], plan: [2, 2], talep: [2, 2], gunnot: [2, 2], duyuru: [2, 2],
  kisisel: [9, 9],                       // kimlik no, uyruk, doğum tarihi, adres: yalnız Genel Müdür + kişisel bilgi yetkilisi
  ynot: [9, 9],                          // yönetici notları: yöneticiler ve usta başları (aşağıda)
  canli: [2, 3],
};
const ruleOf = coll => RULES[coll] || DEF;
const RESERVED = new Set(['kurucu', '__g']);
const KORUMALI = ['rol', 'unvan', 'yetkiler']; // personel kaydında yalnız Genel Müdürün değiştirebileceği alanlar

const json = (o, status = 200, extra = {}) => new Response(JSON.stringify(o), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...extra },
});
const fail = (code, status = 403) => json({ error: code }, status);

// ---------- kullanıcı adı: Türkçe harfler serbest, anahtar ASCII ----------
const trLow = x => String(x || '').replace(/I/g, 'ı').replace(/İ/g, 'i').toLowerCase();
const uKey = x => trLow(x).trim().replace(/ç/g, 'c').replace(/ğ/g, 'g').replace(/ı/g, 'i').replace(/ö/g, 'o').replace(/ş/g, 's').replace(/ü/g, 'u')
  .replace(/[âàá]/g, 'a').replace(/[îí]/g, 'i').replace(/[ûú]/g, 'u').replace(/\s+/g, '');

// ---------- şifre (uygulamadaki SHA.pw ile birebir aynı) ----------
async function pwHash(pw, salt) {
  const e = new TextEncoder(), sb = e.encode(salt);
  let x = new Uint8Array(await crypto.subtle.digest('SHA-256', e.encode(salt + ':' + pw)));
  const m = new Uint8Array(32 + sb.length); m.set(sb, 32);
  for (let i = 0; i < 3000; i++) { m.set(x, 0); x = new Uint8Array(await crypto.subtle.digest('SHA-256', m)); }
  return Array.from(x, b => b.toString(16).padStart(2, '0')).join('');
}
function eq(a, b) { if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
function gizliHesap(env) { // KURUCU gizli değişkeni: "salt:hash"
  const v = (env.KURUCU || '').trim(); const i = v.indexOf(':');
  return i > 0 ? { salt: v.slice(0, i), hash: v.slice(i + 1) } : null;
}

// ---------- belge yardımcıları ----------
const okPath = p => typeof p === 'string' && /^[a-z]{2,20}\/[^\/]{1,200}$/.test(p);
const okColl = c => typeof c === 'string' && /^[a-z]{2,20}$/.test(c);
async function getDoc(env, path) {
  const r = await env.DB.prepare('SELECT data FROM docs WHERE path=?').bind(path).first();
  return r ? JSON.parse(r.data) : null;
}
const today = () => new Date(Date.now() + 3 * 3600e3).toISOString().slice(0, 10); // İstanbul
const isCurrent = p => !!p && !(p.cikis && p.cikis <= today()) && !p.arsiv;

// ---------- oturum ----------
const ipOf = req => req.headers.get('cf-connecting-ip') || 'yerel';
function cookieTok(req) { return (req.headers.get('cookie') || '').match(/(?:^|;\s*)tip_s=([A-Za-z0-9_-]{20,})/)?.[1] || null; }
async function who(req, env) {
  const ctx = { read: 0, write: 0, session: null, gm: false, hesap: false, kisisel: false, rol: '', ad: '', extraW: new Set() };
  const tok = cookieTok(req);
  if (!tok) return ctx;
  const s = await env.DB.prepare('SELECT * FROM oturum WHERE token=?').bind(tok).first();
  if (!s) return ctx;
  if (s.u === '__g') {
    const g = gizliHesap(env);
    if (!g || !eq(g.hash.slice(0, 16), s.t)) return ctx;
    Object.assign(ctx, { session: { u: '__g', empId: '__g', t: s.t }, read: 3, write: 0, gz: true });
    return ctx;
  }
  const h = await getDoc(env, 'hesaplar/' + s.u);
  if (!h || h.aktif === false || !h.hash || h.hash.slice(0, 16) !== s.t) return ctx;
  const p = await getDoc(env, 'personel/' + h.empId);
  if (!isCurrent(p)) return ctx;
  const y = p.yetkiler || {};
  ctx.session = { u: s.u, empId: h.empId, t: s.t };
  ctx.rol = p.rol || 'calisan'; ctx.ad = [p.ad, p.soyad].filter(Boolean).join(' ') + (p.unvan ? ' (' + p.unvan + ')' : '');
  if (p.rol === 'yonetici' && !y.sinirli) {
    ctx.read = 3; ctx.write = 3;
    ctx.gm = p.unvan === 'Genel Müdür' || !!y.unvan;
    ctx.hesap = p.unvan === 'Genel Müdür' || !!y.hesap;
    ctx.kisisel = p.unvan === 'Genel Müdür' || !!y.kisisel;
  } else {
    ctx.read = 2; ctx.write = 2;
    if (p.rol === 'yonetici' && y.sinirli && (y.maasOde || y.bordro)) { ctx.read = 3; ctx.extraW = new Set(['odeme', 'islemlog']); }
  }
  if (Date.now() - s.last > 6 * 3600e3) await env.DB.prepare('UPDATE oturum SET last=? WHERE token=?').bind(Date.now(), tok).run();
  return ctx;
}
function canReadColl(ctx, coll) {
  if (coll === 'hesaplar') return ctx.hesap || !!ctx.gz;
  if (coll === 'kisisel') return ctx.kisisel || !!ctx.gz;
  if (coll === 'ynot') return !!ctx.gz || ctx.read >= 3 || ctx.rol === 'ustabasi' || ctx.rol === 'yonetici';
  return ctx.read >= ruleOf(coll)[0];
}
const canRead = (ctx, path) => canReadColl(ctx, path.split('/')[0]);
function canWrite(ctx, path) {
  if (ctx.gz || !ctx.session) return false;
  const [coll, id] = path.split('/');
  if (coll === 'hesaplar') return ctx.hesap && !RESERVED.has(id);
  if (coll === 'kisisel') return ctx.kisisel;
  if (coll === 'ynot') return ctx.write >= 3 || ctx.rol === 'ustabasi'; // usta başı yalnız 'okundu' işaretler (aşağıda)
  if (ctx.extraW.has(coll)) return true;
  return ctx.write >= ruleOf(coll)[1];
}
const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

// ---------- sorgular ----------
function match(d, w) {
  return (w || []).every(([f, o, v]) => {
    const x = d ? d[f] : undefined;
    switch (o) {
      case '==': return x === v; case '!=': return x !== v;
      case '>=': return x >= v; case '>': return x > v; case '<=': return x <= v; case '<': return x < v;
      case 'in': return Array.isArray(v) && v.includes(x);
      case 'array-contains': return Array.isArray(x) && x.includes(v);
      default: return false;
    }
  });
}
async function runQuery(env, q) {
  if (q.t === 'doc') {
    const r = await env.DB.prepare('SELECT data FROM docs WHERE path=?').bind(q.p).first();
    return { exists: !!r, data: r ? JSON.parse(r.data) : null };
  }
  let sql = 'SELECT id, data FROM docs WHERE coll=?';
  const o = Array.isArray(q.o) && /^[A-Za-z0-9_]{1,40}$/.test(q.o[0]) ? q.o : null;
  if (o) sql += ` ORDER BY json_extract(data,'$.${o[0]}') ${o[1] === 'desc' ? 'DESC' : 'ASC'}`;
  else sql += ' ORDER BY id';
  const lim = Number.isInteger(q.l) && q.l > 0 && q.l <= 5000 ? q.l : 0;
  if (lim && !(q.w && q.w.length)) sql += ' LIMIT ' + lim;
  const { results } = await env.DB.prepare(sql).bind(q.p).all();
  let docs = results.map(r => [r.id, JSON.parse(r.data)]).filter(([, d]) => match(d, q.w));
  if (lim) docs = docs.slice(0, lim);
  return { docs };
}
const collOf = q => q.t === 'doc' ? q.p.split('/')[0] : q.p;
const okQuery = q => q && (q.t === 'doc' ? okPath(q.p) : q.t === 'q' && okColl(q.p));
const bump = (env, colls) => colls.map(c => env.DB.prepare('INSERT INTO meta(coll,rev) VALUES(?,?) ON CONFLICT(coll) DO UPDATE SET rev=MAX(meta.rev+1, excluded.rev)').bind(c, Date.now()));
const upsert = (env, path, data) => { const [coll, id] = path.split('/'); return env.DB.prepare('INSERT INTO docs(path,coll,id,data,updated) VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET data=excluded.data, updated=excluded.updated').bind(path, coll, id, JSON.stringify(data), Date.now()); };

// ---------- canlı veri ----------
const WMO = { 0: 'Açık', 1: 'Çoğunlukla açık', 2: 'Parçalı bulutlu', 3: 'Kapalı', 45: 'Sisli', 48: 'Kırağılı sis', 51: 'Hafif çisenti', 53: 'Çisenti', 55: 'Yoğun çisenti', 56: 'Donan çisenti', 57: 'Donan çisenti', 61: 'Hafif yağmur', 63: 'Yağmurlu', 65: 'Kuvvetli yağmur', 66: 'Donan yağmur', 67: 'Donan yağmur', 71: 'Hafif kar', 73: 'Karlı', 75: 'Yoğun kar', 77: 'Kar taneleri', 80: 'Sağanak', 81: 'Kuvvetli sağanak', 82: 'Şiddetli sağanak', 85: 'Kar sağanağı', 86: 'Yoğun kar sağanağı', 95: 'Gök gürültülü fırtına', 96: 'Dolu ile fırtına', 99: 'Dolu ile fırtına' };
const trZaman = d => { const t = new Date(d.getTime() + 3 * 3600e3).toISOString(); return t.slice(8, 10) + '.' + t.slice(5, 7) + ' ' + t.slice(11, 16); };
const KONUM = env => ({ lat: +(env.KONUM_LAT || 40.8890), lon: +(env.KONUM_LON || 29.1890), ad: env.KONUM_AD || 'Kartal' });

async function havaKur(env, yeni, now) {
  let n = 0; const K = KONUM(env);
  try {
    const r = await fetch(`https://api.open-meteo.com/v1/forecast?latitude=${K.lat}&longitude=${K.lon}&current=temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m&daily=weather_code,temperature_2m_max,temperature_2m_min&timezone=Europe%2FIstanbul&forecast_days=5`);
    if (r.ok) {
      const j = await r.json(), c = j.current, d = j.daily;
      yeni.hava = {
        konum: K.ad, sicaklik: Math.round(c.temperature_2m), durum: WMO[c.weather_code] || '—', nem: Math.round(c.relative_humidity_2m),
        ruzgar: Math.round(c.wind_speed_10m), max: Math.round(d.temperature_2m_max[0]), min: Math.round(d.temperature_2m_min[0]), zaman: trZaman(now),
        gunler: d.time.slice(1, 5).map((t, i) => ({ tarih: t, durum: WMO[d.weather_code[i + 1]] || '—', sicaklik: Math.round(d.temperature_2m_max[i + 1]) })),
      };
      n++;
    }
  } catch (e) { }
  try {
    const r = await fetch('https://www.tcmb.gov.tr/kurlar/today.xml');
    if (r.ok) {
      const x = await r.text();
      const sat = k => { const m = x.match(new RegExp('Kod="' + k + '"[\\s\\S]*?<ForexSelling>([\\d.]+)</ForexSelling>')); return m ? +m[1] : null; };
      const tarih = (x.match(/Tarih="([\d.]+)"/) || [])[1];
      const usd = sat('USD'), eur = sat('EUR');
      if (usd && eur) { yeni.kur = { usd, eur, tarih: tarih || '', kaynak: 'TCMB döviz satış' }; n++; }
    }
  } catch (e) { }
  try {
    const r = await fetch('https://finans.truncgil.com/v4/today.json', { headers: { accept: 'application/json' } });
    if (r.ok) {
      const j = await r.json(); const g = j.GRA || j['gram-altin'];
      const v = g && (g.Selling ?? g.satis ?? g['Satış']);
      const num = typeof v === 'number' ? v : parseFloat(String(v || '').replace(/\./g, '').replace(',', '.'));
      if (num > 100) { yeni.altin = { gram: Math.round(num), kaynak: 'truncgil finans', zaman: trZaman(now) }; n++; }
    }
  } catch (e) { }
  return n;
}

// Trafik: TomTom Traffic Incidents (ücretsiz plan, anahtar gerekir) — konum çevresi 20 km
const KAT = { 0: 'Olay', 1: 'Kaza', 2: 'Sis', 3: 'Tehlikeli yol', 4: 'Yağmur', 5: 'Buzlanma', 6: 'Yoğun trafik', 7: 'Şerit kapalı', 8: 'Yol kapalı', 9: 'Yol çalışması', 10: 'Kuvvetli rüzgâr', 11: 'Su baskını', 14: 'Arızalı araç' };
const SEV = { 0: 'bilinmiyor', 1: 'hafif', 2: 'orta', 3: 'ağır', 4: 'kapalı' };
function km(a, b) { const R = 6371, t = Math.PI / 180; const dLa = (b[1] - a[1]) * t, dLo = (b[0] - a[0]) * t; const x = Math.sin(dLa / 2) ** 2 + Math.cos(a[1] * t) * Math.cos(b[1] * t) * Math.sin(dLo / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(x)); }
async function trafik(env, yeni, now) {
  if (!env.TOMTOM_KEY) return 0;
  const K = KONUM(env), R = 20;
  const dLat = R / 111, dLon = R / (111 * Math.cos(K.lat * Math.PI / 180));
  const bbox = [K.lon - dLon, K.lat - dLat, K.lon + dLon, K.lat + dLat].map(v => v.toFixed(5)).join(',');
  const fields = '{incidents{type,geometry{type,coordinates},properties{iconCategory,magnitudeOfDelay,events{description,code},from,to,length,delay,roadNumbers}}}';
  const url = `https://api.tomtom.com/traffic/services/5/incidentDetails?key=${encodeURIComponent(env.TOMTOM_KEY)}&bbox=${bbox}&fields=${encodeURIComponent(fields)}&language=tr-TR&timeValidityFilter=present`;
  try {
    const r = await fetch(url);
    if (!r.ok) return 0;
    const j = await r.json();
    const merkez = [K.lon, K.lat];
    const L = (j.incidents || []).map(x => {
      const p = x.properties || {}, g = x.geometry || {};
      const c = g.type === 'Point' ? g.coordinates : (g.coordinates || [])[Math.floor((g.coordinates || []).length / 2)];
      return { p, c };
    }).filter(x => x.c && km(merkez, x.c) <= R);
    let yogun = 0, kaza = 0, kapali = 0;
    const items = L.map(({ p }) => {
      const cat = p.iconCategory, mag = p.magnitudeOfDelay ?? 0;
      if (cat === 6) yogun++; if (cat === 1) kaza++; if (cat === 8 || mag === 4) kapali++;
      const yol = (p.roadNumbers || []).join('/');
      const yer = [p.from, p.to].filter(Boolean).join(' → ');
      const ac = (p.events || []).map(e => e.description).filter(Boolean)[0] || KAT[cat] || 'Olay';
      const dk = p.delay ? Math.round(p.delay / 60) : 0;
      const t = [yol, yer].filter(Boolean).join(' ') + ': ' + ac + (dk ? ' · ' + dk + ' dk gecikme' : '') + (p.length ? ' · ' + (p.length / 1000).toFixed(1).replace('.', ',') + ' km' : '');
      return { t, s: mag === 4 ? 3 : Math.min(3, mag), d: p.delay || 0, m: mag };
    }).sort((a, b) => (b.m === 4 ? 5 : b.m) - (a.m === 4 ? 5 : a.m) || b.d - a.d).slice(0, 12).map(({ t, s }) => ({ t, s }));
    const ozet = items.length
      ? `${K.ad} çevresi 20 km: ${yogun} yoğunluk, ${kaza} kaza, ${kapali} kapalı yol`
      : `${K.ad} çevresi 20 km: bildirilen yoğunluk yok — yollar akıcı`;
    yeni.trafik = { ozet, maddeler: items, zaman: trZaman(now).slice(6), kaynak: 'TomTom' };
    return 1;
  } catch (e) { return 0; }
}
async function canliGuncelle(env, { hava = true, traf = true } = {}) {
  await ensureSchema(env);
  const yeni = { ...((await getDoc(env, 'canli/veri')) || {}) };
  const now = new Date();
  let n = 0;
  if (hava) n += await havaKur(env, yeni, now);
  if (traf) n += await trafik(env, yeni, now);
  if (!n) return;
  if (hava) yeni.guncelleme = new Date(now.getTime() + 3 * 3600e3).toISOString().slice(0, 19) + '+03:00';
  await env.DB.batch([upsert(env, 'canli/veri', yeni), ...bump(env, ['canli'])]);
}

// ---------- istekler ----------
async function body(req) { try { return await req.json(); } catch { return null; } }
function rid() { const a = new Uint8Array(24); crypto.getRandomValues(a); return btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
const setCookie = (tok, age) => `tip_s=${tok}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;

async function api(req, env, path) {
  await ensureSchema(env);
  if (req.method === 'POST' && req.headers.get('x-tip') !== '1') return fail('csrf');
  const ctx = await who(req, env);

  if (path === 'me') return json({ owner: false, session: ctx.session });

  if (path === 'login' && req.method === 'POST') {
    const b = await body(req) || {};
    const u = uKey(b.u), p = String(b.p || '');
    const ip = ipOf(req), since = Date.now() - 15 * 60e3;
    const cnt = await env.DB.prepare("SELECT SUM(k=?) AS ip, SUM(k=?) AS us FROM deneme WHERE ts>?").bind('ip:' + ip, 'u:' + u, since).first();
    if ((cnt && (cnt.ip >= 20 || cnt.us >= 8))) return fail('cok_deneme', 429);
    let ok = null;
    if (/^[a-z0-9._-]{2,40}$/.test(u) && p.length <= 100) {
      if (u === 'kurucu') {
        const g = gizliHesap(env);
        if (g && eq(await pwHash(p, g.salt), g.hash)) ok = { u: '__g', empId: '__g', t: g.hash.slice(0, 16) };
      } else {
        const h = await getDoc(env, 'hesaplar/' + u);
        if (h && h.aktif !== false && h.hash && h.salt && eq(await pwHash(p, h.salt), h.hash)) {
          if (!isCurrent(await getDoc(env, 'personel/' + h.empId))) return fail('pasif');
          ok = { u, empId: h.empId, t: h.hash.slice(0, 16) };
        }
      }
    }
    if (!ok) {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO deneme(k,ts) VALUES(?,?),(?,?)').bind('ip:' + ip, Date.now(), 'u:' + u, Date.now()),
        env.DB.prepare('DELETE FROM deneme WHERE ts<?').bind(Date.now() - 86400e3),
      ]);
      return fail('hatali', 401);
    }
    const tok = rid();
    await env.DB.batch([
      env.DB.prepare('INSERT INTO oturum(token,u,emp,t,ip,created,last) VALUES(?,?,?,?,?,?,?)').bind(tok, ok.u, ok.empId, ok.t, ip, Date.now(), Date.now()),
      env.DB.prepare('DELETE FROM oturum WHERE last<?').bind(Date.now() - 90 * 86400e3),
    ]);
    return json({ session: ok }, 200, { 'set-cookie': setCookie(tok, 60 * 86400) });
  }

  if (path === 'logout' && req.method === 'POST') {
    const tok = cookieTok(req);
    if (tok) await env.DB.prepare('DELETE FROM oturum WHERE token=?').bind(tok).run();
    return json({ ok: true }, 200, { 'set-cookie': setCookie('x', 0) });
  }

  if (path === 'pw' && req.method === 'POST') {
    if (!ctx.session || ctx.gz) return fail('oturum', 401);
    const b = await body(req) || {};
    const h = await getDoc(env, 'hesaplar/' + ctx.session.u);
    if (!h || !eq(await pwHash(String(b.old || ''), h.salt), h.hash)) return fail('eski_sifre', 400);
    const nw = String(b.new || '');
    if (nw.length < 6 || nw.length > 100) return fail('kisa', 400);
    const a = new Uint8Array(8); crypto.getRandomValues(a);
    const salt = Array.from(a, x => x.toString(16).padStart(2, '0')).join('');
    const hash = await pwHash(nw, salt), t = hash.slice(0, 16), tok = cookieTok(req);
    await env.DB.batch([
      upsert(env, 'hesaplar/' + ctx.session.u, { ...h, salt, hash, ts: Date.now() }),
      env.DB.prepare('DELETE FROM oturum WHERE u=? AND token<>?').bind(ctx.session.u, tok),
      env.DB.prepare('UPDATE oturum SET t=? WHERE token=?').bind(t, tok),
      ...bump(env, ['hesaplar']),
    ]);
    return json({ ok: true, t });
  }

  if (path === 'sync' && req.method === 'POST') {
    const b = await body(req) || {};
    const subs = Array.isArray(b.subs) ? b.subs.slice(0, 60) : [];
    const { results } = await env.DB.prepare('SELECT coll, rev FROM meta').all();
    const rev = Object.fromEntries(results.map(r => [r.coll, r.rev]));
    const out = {};
    for (const s of subs) {
      if (!okQuery(s)) { out[s.k] = { e: 'invalid-argument' }; continue; }
      const r = (rev[collOf(s)] || 0) * 10 + (ctx.read + (ctx.hesap ? 5 : 0)); // yetki değişince de yeniden gönder
      if (s.r === r) continue;
      const allowed = s.t === 'doc' ? canRead(ctx, s.p) : canReadColl(ctx, s.p);
      if (!allowed) { out[s.k] = { e: 'permission-denied', r }; continue; }
      out[s.k] = { r, v: await runQuery(env, s) };
    }
    return json({ out, s: ctx.session ? ctx.session.t : null });
  }

  if (path === 'get' && req.method === 'POST') {
    const q = await body(req);
    if (!okQuery(q)) return fail('invalid-argument', 400);
    if (!(q.t === 'doc' ? canRead(ctx, q.p) : canReadColl(ctx, q.p))) return fail('permission-denied');
    return json(await runQuery(env, q));
  }

  if (path === 'w' && req.method === 'POST') {
    const b = await body(req) || {};
    const ops = Array.isArray(b.ops) ? b.ops.slice(0, 500) : [];
    if (!ops.length) return fail('invalid-argument', 400);
    const st = [], colls = new Set();
    for (const o of ops) {
      if (!okPath(o.p) || !['set', 'del', 'upd'].includes(o.op)) return fail('invalid-argument', 400);
      if (!canWrite(ctx, o.p)) return fail('permission-denied');
      const coll = o.p.split('/')[0];
      colls.add(coll);
      const needCur = o.op === 'upd' || (coll === 'personel' && !ctx.gm) || coll === 'ynot';
      const cur = needCur ? await getDoc(env, o.p) : null;
      if (o.op === 'del') {
        if (coll === 'personel' && !ctx.gm && cur && (cur.rol === 'yonetici' || cur.yetkiler || cur.unvan)) return fail('permission-denied');
        if (coll === 'ynot' && ctx.write < 3) return fail('permission-denied');
        st.push(env.DB.prepare('DELETE FROM docs WHERE path=?').bind(o.p));
        continue;
      }
      let d = o.d;
      if (o.op === 'upd') { if (!cur) return fail('not-found', 404); d = { ...cur, ...d }; }
      if (!d || typeof d !== 'object' || Array.isArray(d)) return fail('invalid-argument', 400);
      if (coll === 'personel' && !ctx.gm) {
        const base = cur || { rol: 'calisan' };
        if (KORUMALI.some(k => !same(base[k] ?? (k === 'rol' ? 'calisan' : undefined), d[k] ?? (k === 'rol' ? 'calisan' : undefined)))) return fail('permission-denied');
      }
      if (coll === 'ynot') {
        if (ctx.write < 3) { // usta başı: yalnız kendisine yazılmış notu 'okundu' işaretleyebilir
          if (!cur || cur.ustabasi !== ctx.session.empId || cur.okundu || !d.okundu) return fail('permission-denied');
          const { okundu, ...rest } = d; const { okundu: _o, ...crest } = cur;
          if (!same(rest, crest)) return fail('permission-denied');
          d = { ...cur, okundu: { ts: Date.now(), ad: ctx.ad, by: ctx.session.empId } };
        }
        if (d.okundu && (!cur || !cur.okundu)) { // okunma kaydı: işlem geçmişine sunucu yazar
          const ts = Date.now();
          st.push(upsert(env, 'islemlog/' + ts + '-yn' + Math.random().toString(36).slice(2, 7), { ts, tur: 'Yönetici notu', empId: cur ? cur.ustabasi : d.ustabasi, metin: 'Not okundu: “' + String((cur || d).metin || '').slice(0, 100) + '” (yazan: ' + ((cur || d).ad || '') + ')', ad: ctx.ad }));
          colls.add('islemlog');
        }
      }
      if (JSON.stringify(d).length > 900000) return fail('too-large', 413);
      st.push(upsert(env, o.p, d));
    }
    await env.DB.batch([...st, ...bump(env, [...colls])]);
    return json({ ok: true });
  }

  if (path === 'import' && req.method === 'POST') {
    if (!ctx.gm) return fail('permission-denied');
    const b = await body(req) || {};
    const docs = b.docs && typeof b.docs === 'object' ? b.docs : null;
    if (!docs) return fail('invalid-argument', 400);
    const entries = Object.entries(docs).filter(([p]) => okPath(p) && !(p.startsWith('hesaplar/') && RESERVED.has(p.split('/')[1])) && !p.startsWith('sys/'));
    const colls = [...new Set(entries.map(([p]) => p.split('/')[0]))];
    const st = colls.map(c => env.DB.prepare('DELETE FROM docs WHERE coll=?').bind(c));
    for (const [p, d] of entries) st.push(upsert(env, p, d));
    for (let i = 0; i < st.length; i += 400) await env.DB.batch(st.slice(i, i + 400));
    await env.DB.batch(bump(env, colls));
    return json({ ok: true, adet: entries.length, koleksiyon: colls.length });
  }

  if (path === 'canli' && req.method === 'POST') {
    if (ctx.write < 3) return fail('permission-denied');
    await canliGuncelle(env);
    return json({ ok: true });
  }

  return fail('not-found', 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/')) {
      try { return await api(req, env, url.pathname.slice(5)); }
      catch (e) { return json({ error: 'sunucu', detay: String(e && e.message || e).slice(0, 200) }, 500); }
    }
    return env.ASSETS.fetch(req);
  },
  // Her 15 dakikada bir: trafik. Saat başlarında (dakika 0–14): hava, kur ve altın da.
  async scheduled(event, env, ctx) {
    const dk = new Date(event.scheduledTime).getUTCMinutes();
    ctx.waitUntil(canliGuncelle(env, { hava: dk < 15, traf: true }));
  },
};
