'use strict';

// Worksheet Desk — Vercel Serverless Function
// Actions: health | worksheets | login | submit | load | save | grade
const crypto = require('crypto');
const E = process.env;

const MAX_STORED_CHARS = 800_000;
const MAX_WORKSHEETS = 100;
const MAX_QUESTIONS = 200;
const MAX_OPTIONS = 20;
const TOKEN_TTL_MS = 8 * 60 * 60 * 1000;

async function rd(...cmd) {
  const url = E.KV_REST_API_URL || E.UPSTASH_REDIS_REST_URL;
  const token = E.KV_REST_API_TOKEN || E.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error('NO_DB');

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + token,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(cmd)
  });

  if (!response.ok) throw new Error('REDIS_HTTP_' + response.status);

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error('REDIS_BAD_RESPONSE');
  }
  if (data.error) throw new Error('REDIS_COMMAND_FAILED');
  return data.result;
}

function out(res, status, value) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify(value));
}

function body(req) {
  try {
    const value = typeof req.body === 'string'
      ? JSON.parse(req.body || '{}')
      : (req.body || {});
    return value && typeof value === 'object' && !Array.isArray(value)
      ? value : {};
  } catch {
    return {};
  }
}

const sha = value => crypto.createHash('sha256').update(String(value)).digest();

function same(a, b) {
  return crypto.timingSafeEqual(sha(a), sha(b));
}

function secret() {
  if (!E.TOKEN_SECRET || E.TOKEN_SECRET.length < 32) {
    throw new Error('NO_SECRET');
  }
  return E.TOKEN_SECRET;
}

function mac(payload) {
  return crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
}

function sign() {
  const now = Date.now();
  const payload = Buffer.from(JSON.stringify({
    iat: now,
    exp: now + TOKEN_TTL_MS
  })).toString('base64url');
  return payload + '.' + mac(payload);
}

function authed(req) {
  try {
    const header = req.headers.authorization || '';
    const match = /^Bearer\s+(\S+)$/i.exec(header);
    if (!match) return false;

    const parts = match[1].split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) return false;
    const [payload, signature] = parts;
    const expected = Buffer.from(mac(payload));
    const actual = Buffer.from(signature);

    if (actual.length !== expected.length ||
        !crypto.timingSafeEqual(actual, expected)) return false;

    const token = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const now = Date.now();
    return !!token &&
      Number.isSafeInteger(token.iat) &&
      Number.isSafeInteger(token.exp) &&
      token.iat <= now &&
      token.exp > now &&
      token.exp > token.iat &&
      token.exp - token.iat <= TOKEN_TTL_MS;
  } catch {
    return false;
  }
}

// Vercel supplies x-forwarded-for. Hash IPs before using them in Redis keys.
function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const first = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : '';
  const real = req.headers['x-real-ip'];
  const ip = first || (typeof real === 'string' ? real.trim() : '');
  return ip && ip.length <= 100 ? ip : 'unknown';
}

function ipHash(ip) {
  return crypto.createHash('sha256').update(ip).digest('hex');
}

async function hit(key, max, seconds) {
  const n = Number(await rd('INCR', key));
  if (!Number.isSafeInteger(n) || n < 1) throw new Error('RATE_LIMIT_FAILED');
  if (n === 1) await rd('EXPIRE', key, seconds);
  return n <= max;
}

function parseJson(value, fallback) {
  if (value == null || value === '') return fallback;
  try {
    return JSON.parse(value);
  } catch {
    throw new Error('STORED_DATA_INVALID');
  }
}

function validWorksheet(w) {
  if (!w || typeof w !== 'object' || Array.isArray(w)) return false;
  if (typeof w.id !== 'number' || !Number.isSafeInteger(w.id) ||
      typeof w.title !== 'string' || !w.title.trim() ||
      w.title.length > 200 || !Array.isArray(w.q) ||
      w.q.length > MAX_QUESTIONS) return false;

  return w.q.every(q => {
    if (!q || typeof q !== 'object' || Array.isArray(q) ||
        typeof q.q !== 'string' || !q.q.trim() || q.q.length > 3000) return false;

    if (q.t === 'mc') {
      return Array.isArray(q.o) &&
        q.o.length >= 2 && q.o.length <= MAX_OPTIONS &&
        q.o.every(o => typeof o === 'string' && o.trim() && o.length <= 500) &&
        Number.isInteger(q.a) && q.a >= 0 && q.a < q.o.length;
    }
    return q.t === 'tx' && (q.a == null || typeof q.a === 'string');
  });
}

function pubOf(wss) {
  return wss.map(w => ({
    id: w.id,
    title: w.title,
    q: w.q.map(q => q.t === 'mc'
      ? { t: 'mc', q: q.q, o: q.o }
      : { t: 'tx', q: q.q })
  }));
}

function pts(w) {
  return w.q.reduce((total, q) => total + (q.t === 'mc' ? 1 : 2), 0);
}

// Upstash HGETALL normally returns alternating field/value entries.
// Also accept object-shaped responses for compatible Redis REST gateways.
function hashEntries(hash) {
  if (hash == null) return [];
  if (Array.isArray(hash)) {
    if (hash.length % 2 !== 0) throw new Error('STORED_DATA_INVALID');
    const result = [];
    for (let i = 0; i < hash.length; i += 2) result.push([hash[i], hash[i + 1]]);
    return result;
  }
  if (typeof hash === 'object') return Object.entries(hash);
  throw new Error('STORED_DATA_INVALID');
}

module.exports = async (req, res) => {
  try {
    const action = new URL(req.url, 'http://localhost').searchParams.get('a');
    const ip = ipHash(clientIp(req));

    if (action === 'health') {
      let db = Boolean(
        (E.KV_REST_API_URL && E.KV_REST_API_TOKEN) ||
        (E.UPSTASH_REDIS_REST_URL && E.UPSTASH_REDIS_REST_TOKEN)
      );
      if (db) {
        try { await rd('PING'); } catch { db = false; }
      }
      return out(res, 200, {
        db,
        passcode: Boolean(E.TEACHER_PASSCODE),
        secret: Boolean(E.TOKEN_SECRET && E.TOKEN_SECRET.length >= 32)
      });
    }

    if (action === 'worksheets') {
      const worksheets = parseJson(await rd('GET', 'pub'), []);
      if (!Array.isArray(worksheets)) throw new Error('STORED_DATA_INVALID');
      return out(res, 200, { worksheets });
    }

    // load is read-only but the existing teacher frontend sends POST.
    if (action === 'load') {
      if (!authed(req)) return out(res, 401, { error: 'Please sign in again.' });
      const wss = parseJson(await rd('GET', 'wss'), []);
      if (!Array.isArray(wss)) throw new Error('STORED_DATA_INVALID');
      const entries = hashEntries(await rd('HGETALL', 'subs'));
      const subs = entries.map(([, value]) => {
        const sub = parseJson(value, null);
        if (!sub || typeof sub !== 'object' || !sub.ws || !sub.ans) {
          throw new Error('STORED_DATA_INVALID');
        }
        return sub;
      }).sort((a, b) => (Date.parse(b.ts) || 0) - (Date.parse(a.ts) || 0));
      return out(res, 200, { wss, subs });
    }

    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return out(res, 405, { error: 'Use POST' });
    }

    const b = body(req);

    if (action === 'login') {
      if (!E.TEACHER_PASSCODE) {
        return out(res, 503, { error: 'TEACHER_PASSCODE is not set in Vercel yet.' });
      }
      secret();

      const failKey = 'fail:' + ip;
      const fails = Number(await rd('GET', failKey)) || 0;
      if (fails >= 5) {
        return out(res, 429, { error: 'Too many wrong tries. Wait 5 minutes.' });
      }

      if (typeof b.passcode !== 'string' || !same(b.passcode, E.TEACHER_PASSCODE)) {
        const n = Number(await rd('INCR', failKey));
        if (n === 1) await rd('EXPIRE', failKey, 300);
        return out(res, 401, {
          error: 'Wrong passcode. ' + Math.max(0, 5 - n) + ' tries left.'
        });
      }

      await rd('DEL', failKey);
      return out(res, 200, { token: sign() });
    }

    if (action === 'submit') {
      const name = typeof b.name === 'string' ? b.name.trim().slice(0, 60) : '';
      if (!name) return out(res, 400, { error: 'Enter your name first.' });

      const wid = String(b.wid ?? '');
      if (!wid || wid.length > 200) {
        return out(res, 400, { error: 'Invalid worksheet.' });
      }

      const wss = parseJson(await rd('GET', 'wss'), []);
      if (!Array.isArray(wss)) throw new Error('STORED_DATA_INVALID');
      const worksheet = wss.find(w => String(w.id) === wid);
      if (!worksheet || !validWorksheet(worksheet)) {
        return out(res, 404, { error: 'This worksheet is no longer available.' });
      }

      if (!(await hit('rl:' + ip, 30, 60))) {
        return out(res, 429, { error: 'Too many submissions. Wait a minute and try again.' });
      }

      const given = b.ans && typeof b.ans === 'object' && !Array.isArray(b.ans)
        ? b.ans : {};
      const ans = {};
      worksheet.q.forEach((q, i) => {
        const value = given[i];
        if (q.t === 'mc') {
          if (Number.isInteger(value) && value >= 0 && value < q.o.length) ans[i] = value;
        } else if (typeof value === 'string' && value.trim()) {
          ans[i] = value.slice(0, 3000);
        }
      });

      // Keep numeric IDs for compatibility with the existing teacher.html.
      const id = Number(await rd('INCR', 'subs:seq'));
      if (!Number.isSafeInteger(id) || id < 1) throw new Error('ID_GENERATION_FAILED');
      const submission = {
        id,
        name,
        ts: new Date().toISOString(),
        wid: worksheet.id,
        ws: worksheet,
        ans,
        status: 'Pending Review',
        score: null,
        fb: ''
      };
      await rd('HSET', 'subs', String(id), JSON.stringify(submission));
      return out(res, 200, { ok: true });
    }

    if (!authed(req)) {
      return out(res, 401, { error: 'Please sign in again.' });
    }

    if (action === 'save') {
      const wss = b.wss;
      if (!Array.isArray(wss) || wss.length > MAX_WORKSHEETS ||
          !wss.every(validWorksheet)) {
        return out(res, 400, { error: 'Invalid worksheet data.' });
      }

      const ids = wss.map(w => String(w.id));
      if (new Set(ids).size !== ids.length) {
        return out(res, 400, { error: 'Worksheet IDs must be unique.' });
      }

      const serialized = JSON.stringify(wss);
      const publicSerialized = JSON.stringify(pubOf(wss));
      if (serialized.length > MAX_STORED_CHARS ||
          publicSerialized.length > MAX_STORED_CHARS) {
        return out(res, 413, { error: 'Too much data. Remove some worksheets.' });
      }

      // One Redis EVAL makes both values update atomically.
      await rd(
        'EVAL',
        "redis.call('SET', KEYS[1], ARGV[1]); redis.call('SET', KEYS[2], ARGV[2]); return 1",
        2, 'wss', 'pub', serialized, publicSerialized
      );
      return out(res, 200, { ok: true });
    }

    if (action === 'grade') {
      const id = String(b.id ?? '');
      if (!id || id.length > 200) return out(res, 400, { error: 'Invalid submission ID.' });

      const raw = await rd('HGET', 'subs', id);
      if (!raw) return out(res, 404, { error: 'Submission not found.' });
      const submission = parseJson(raw, null);
      if (!submission || !submission.ws || !validWorksheet(submission.ws)) {
        throw new Error('STORED_DATA_INVALID');
      }

      const score = b.score;
      const max = pts(submission.ws);
      if (typeof score !== 'number' || !Number.isFinite(score) ||
          !Number.isInteger(score) || score < 0 || score > max) {
        return out(res, 400, {
          error: 'Score must be a whole number between 0 and ' + max + '.'
        });
      }

      submission.score = score;
      submission.fb = typeof b.fb === 'string' ? b.fb.slice(0, 2000) : '';
      submission.status = 'Marked';
      await rd('HSET', 'subs', String(submission.id), JSON.stringify(submission));
      return out(res, 200, { ok: true, sub: submission });
    }

    return out(res, 404, { error: 'Unknown action.' });
  } catch (error) {
    // Log details server-side only; don't expose database errors or secrets.
    console.error('[Worksheet Desk]', error.message);

    if (error.message === 'NO_DB') {
      return out(res, 503, { error: 'The database is not connected yet.' });
    }
    if (error.message === 'NO_SECRET') {
      return out(res, 503, {
        error: 'TOKEN_SECRET must be a random secret of at least 32 characters.'
      });
    }
    if (error.message === 'STORED_DATA_INVALID') {
      return out(res, 500, { error: 'Stored data is invalid. Check server logs.' });
    }
    return out(res, 503, { error: 'Server error. Please try again.' });
  }
};
