// Worksheet Desk server. One Vercel function, five actions: ?a=health|worksheets|login|submit|load|save|grade
const crypto = require('crypto');
const E = process.env;

async function rd(...cmd) {
  const url = E.KV_REST_API_URL || E.UPSTASH_REDIS_REST_URL;
  const tok = E.KV_REST_API_TOKEN || E.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !tok) throw new Error('NO_DB');
  const r = await fetch(url, { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: JSON.stringify(cmd) });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
const out = (res, code, obj) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store'); res.end(JSON.stringify(obj)); };
const body = req => { try { return typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {}); } catch (e) { return {}; } };
const sha = x => crypto.createHash('sha256').update(String(x)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const secret = () => { if (!E.TOKEN_SECRET) throw new Error('NO_SECRET'); return E.TOKEN_SECRET; };
const mac = p => crypto.createHmac('sha256', secret()).update(p).digest('base64url');
const sign = () => { const p = Buffer.from(JSON.stringify({ exp: Date.now() + 8 * 3600e3 })).toString('base64url'); return p + '.' + mac(p); };
function authed(req) {
  const [p, s] = (req.headers.authorization || '').replace(/^Bearer /, '').split('.');
  if (!p || !s) return false;
  const ok = mac(p);
  if (s.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(ok))) return false;
  try { return JSON.parse(Buffer.from(p, 'base64url').toString()).exp > Date.now(); } catch (e) { return false; }
}
async function hit(key, max, sec) { const n = await rd('INCR', key); if (n === 1) await rd('EXPIRE', key, sec); return n <= max; }
const pubOf = wss => wss.map(w => ({ id: w.id, title: w.title, q: w.q.map(q => q.t === 'mc' ? { t: 'mc', q: q.q, o: q.o } : { t: 'tx', q: q.q }) }));
const pts = w => w.q.reduce((n, q) => n + (q.t === 'mc' ? 1 : 2), 0);

module.exports = async (req, res) => {
  try {
    const a = new URL(req.url, 'http://x').searchParams.get('a');
    
    // 安全解析 IP
    const ipHeader = req.headers['x-forwarded-for'] || '';
    const ip = ipHeader ? ipHeader.split(',')[0].trim() : 'x';

    // 1. 无动作或健康检查：允许 GET
    if (!a || a === 'health') {
      let db = !!((E.KV_REST_API_URL && E.KV_REST_API_TOKEN) || (E.UPSTASH_REDIS_REST_URL && E.UPSTASH_REDIS_REST_TOKEN));
      if (db) { try { await rd('PING'); } catch (e) { db = false; } }
      return out(res, 200, { db, passcode: !!E.TEACHER_PASSCODE, secret: !!E.TOKEN_SECRET });
    }
    
    // 2. 获取公开作业模板：允许 GET
    if (a === 'worksheets') {
      const r = await rd('GET', 'pub');
      return out(res, 200, { worksheets: r ? JSON.parse(r) : [] });
    }
    
    // 3. 教师端初始化加载数据：允许 GET 方式触发（完美解决报错）
    if (a === 'load') {
      if (!authed(req)) return out(res, 401, { error: 'Please sign in again.' });
      const wss = JSON.parse((await rd('GET', 'wss')) || '[]');
      const h = (await rd('HGETALL', 'subs')) || [];
      const vals = Array.isArray(h) ? h.filter((_, i) => i % 2) : Object.values(h);
      const subs = vals.map(v => JSON.parse(v)).sort((x, y) => y.id - x.id);
      return out(res, 200, { wss, subs });
    }

    // 4. 其余涉及敏感、更新数据库的操作强制走 POST
    if (req.method !== 'POST') return out(res, 405, { error: 'Use POST' });
    const b = body(req);

    if (a === 'login') {
      if (!E.TEACHER_PASSCODE) return out(res, 503, { error: 'TEACHER_PASSCODE is not set in Vercel yet.' });
      secret();
      if ((Number(await rd('GET', 'fail:' + ip)) || 0) >= 5) return out(res, 429, { error: 'Too many wrong tries. Wait 5 minutes.' });
      if (typeof b.passcode !== 'string' || !same(b.passcode, E.TEACHER_PASSCODE)) {
        const n = await rd('INCR', 'fail:' + ip); if (n === 1) await rd('EXPIRE', 'fail:' + ip, 300);
        return out(res, 401, { error: 'Wrong passcode. ' + Math.max(0, 5 - n) + ' tries left.' });
      }
      await rd('DEL', 'fail:' + ip);
      return out(res, 200, { token: sign() });
    }

    if (a === 'submit') {
      const name = String(b.name || '').trim().slice(0, 60);
      if (!name) return out(res, 400, { error: 'Enter your name first.' });
      if (!(await hit('rl:' + ip, 30, 60))) return out(res, 429, { error: 'Too many submissions. Wait a minute and try again.' });
      const w = JSON.parse((await rd('GET', 'wss')) || '[]').find(x => String(x.id) === String(b.wid));
      if (!w) return out(res, 404, { error: 'This worksheet is no longer available.' });
      const ans = {}, given = b.ans && typeof b.ans === 'object' ? b.ans : {};
      w.q.forEach((q, i) => {
        const v = given[i];
        if (q.t === 'mc') { if (Number.isInteger(v) && v >= 0 && v < q.o.length) ans[i] = v; }
        else if (typeof v === 'string' && v.trim()) ans[i] = v.slice(0, 3000);
      });
      const id = Date.now() * 1000 + Math.floor(Math.random() * 1000);
      await rd('HSET', 'subs', String(id), JSON.stringify({ id, name, ts: new Date().toISOString(), wid: w.id, ws: w, ans, status: 'Pending Review', score: null, fb: '' }));
      return out(res, 200, { ok: true });
    }

    if (!authed(req)) return out(res, 401, { error: 'Please sign in again.' });

    if (a === 'save') {
      const wss = b.wss;
      if (!Array.isArray(wss) || wss.length > 100 || wss.some(w => !w || typeof w.title !== 'string' || !Array.isArray(w.q))) return out(res, 400, { error: 'Invalid worksheet data.' });
      const s = JSON.stringify(wss);
      if (s.length > 800000) return out(res, 413, { error: 'Too much data. Remove some worksheets.' });
      await rd('SET', 'wss', s);
      await rd('SET', 'pub', JSON.stringify(pubOf(wss)));
      return out(res, 200, { ok: true });
    }
    if (a === 'grade') {
      const r = await rd('HGET', 'subs', String(b.id));
      if (!r) return out(res, 404, { error: 'Submission not found.' });
      const s = JSON.parse(r), v = Number(b.score);
      if (!(v >= 0 && v <= pts(s.ws))) return out(res, 400, { error: 'Score must be between 0 and ' + pts(s.ws) + '.' });
      s.score = v; s.fb = String(b.fb || '').slice(0, 2000); s.status = 'Marked';
      await rd('HSET', 'subs', String(s.id), JSON.stringify(s));
      return out(res, 200, { ok: true, sub: s });
    }
    return out(res, 404, { error: 'Unknown action' });
  } catch (e) {
    const m = e.message;
    return out(res, 503, { error: m === 'NO_DB' ? 'The database is not connected yet.' : m === 'NO_SECRET' ? 'TOKEN_SECRET is not set in Vercel yet.' : 'Server error. Please try again.' });
  }
};
