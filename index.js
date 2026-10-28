// api/index.js: accounts + email OTP for Vercel (Node.js serverless function).
// Needs these Environment Variables in Vercel:
//   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS  (your email account's SMTP login)
//   SESSION_SECRET                              (any long random text)
//   SHOP_NAME, FROM_EMAIL                       (optional)
// plus an Upstash Redis database connected under Vercel > Storage.
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const SHOP = process.env.SHOP_NAME || 'Your Chicken Farm';
const SECRET = process.env.SESSION_SECRET || '';
const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const OTP_TTL = 600, MAX_TRIES = 5, RESEND_WAIT = 60;

async function kv(cmd) {
  const r = await fetch(KV_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + KV_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
const getUser = async (e) => { const v = await kv(['GET', 'user:' + e]); return v ? JSON.parse(v) : null; };
const saveUser = (u) => kv(['SET', 'user:' + u.email, JSON.stringify(u)]);

const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const hashPw = (pw) => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); };
const checkPw = (pw, stored) => { const [s, h] = stored.split(':'); return same(crypto.scryptSync(pw, s, 64).toString('hex'), h); };
const otpHash = (o, e) => crypto.createHmac('sha256', SECRET).update(o + ':' + e).digest('hex');
const sign = (p) => { const d = Buffer.from(JSON.stringify(p)).toString('base64url'); return d + '.' + crypto.createHmac('sha256', SECRET).update(d).digest('base64url'); };
const unsign = (t) => {
  if (!t) return null;
  const [d, s] = t.split('.');
  if (!d || !s || !same(s, crypto.createHmac('sha256', SECRET).update(d).digest('base64url'))) return null;
  try { const p = JSON.parse(Buffer.from(d, 'base64url').toString()); return p.exp > Date.now() ? p : null; } catch { return null; }
};
const readCookie = (req, name) => {
  const m = (req.headers.cookie || '').split(';').map((c) => c.trim()).find((c) => c.startsWith(name + '='));
  return m ? m.slice(name.length + 1) : '';
};
const setSession = (res, email) =>
  res.setHeader('Set-Cookie', 'sid=' + sign({ e: email, exp: Date.now() + 30 * 864e5 }) + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000');
const send = (res, status, obj) => res.status(status).json(obj);
const fail = (res, msg, status = 400) => send(res, status, { ok: false, error: msg });

async function sendOtp(u) {
  if (Date.now() - (u.otp_sent || 0) < RESEND_WAIT * 1000) return 'Please wait a minute before asking for another code.';
  const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  Object.assign(u, { otp_hash: otpHash(otp, u.email), otp_exp: Date.now() + OTP_TTL * 1000, otp_tries: 0, otp_sent: Date.now() });
  await saveUser(u);
  const mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: +process.env.SMTP_PORT || 465,
    secure: (+process.env.SMTP_PORT || 465) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  try {
    await mailer.sendMail({
      from: `"${SHOP}" <${process.env.FROM_EMAIL || process.env.SMTP_USER}>`,
      to: u.email,
      subject: SHOP + ' verification code',
      text: `Hi ${u.name},\n\nYour ${SHOP} verification code is:\n\n    ${otp}\n\nIt expires in ${OTP_TTL / 60} minutes. If you didn't create an account, ignore this email.\n`,
    });
  } catch (e) {
    console.error(e);
    return 'We could not send the email. Please try again later.';
  }
  return null;
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return fail(res, 'Use POST.', 405);
  if (!SECRET || !KV_URL || !KV_TOKEN || !process.env.SMTP_HOST) return fail(res, 'The server is not set up yet (missing settings).', 500);
  const b = req.body && typeof req.body === 'object' ? req.body : {};
  const action = String(b.action || '');
  const email = String(b.email || '').trim().toLowerCase();
  try {
    if (action === 'me') {
      const s = unsign(readCookie(req, 'sid'));
      const u = s && (await getUser(s.e));
      return u && u.verified ? send(res, 200, { ok: true, email: u.email, name: u.name }) : send(res, 200, { ok: false });
    }
    if (action === 'logout') {
      res.setHeader('Set-Cookie', 'sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
      return send(res, 200, { ok: true });
    }
    if (!['signup', 'login', 'verify', 'resend'].includes(action)) return fail(res, 'Unknown action.', 404);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) return fail(res, 'Enter a valid email address.');
    let u = await getUser(email);

    if (action === 'signup') {
      const name = String(b.name || '').trim(), pw = String(b.password || '');
      if (!name || name.length > 40) return fail(res, 'Enter your name (up to 40 characters).');
      if (pw.length < 6) return fail(res, 'Password must be at least 6 characters.');
      if (u && u.verified) return fail(res, 'That email already has an account. Sign in instead.', 409);
      u = { ...(u || {}), email, name, pass: hashPw(pw), verified: false };
      await saveUser(u);
      const err = await sendOtp(u);
      return err ? fail(res, err, 429) : send(res, 200, { ok: true, needs_verify: true });
    }
    if (action === 'resend') {
      if (!u || u.verified) return fail(res, 'Nothing to confirm for that email.');
      const err = await sendOtp(u);
      return err ? fail(res, err, 429) : send(res, 200, { ok: true });
    }
    if (action === 'verify') {
      const otp = String(b.otp || '').replace(/\D/g, '');
      if (!u || !u.otp_hash) return fail(res, 'Request a new code first.');
      if (Date.now() > u.otp_exp) return fail(res, 'That code has expired. Request a new one.');
      if (u.otp_tries >= MAX_TRIES) return fail(res, 'Too many wrong attempts. Request a new code.', 429);
      if (!same(otpHash(otp, email), u.otp_hash)) {
        u.otp_tries += 1;
        await saveUser(u);
        return fail(res, "That code doesn't match. Check it and try again.");
      }
      Object.assign(u, { verified: true, otp_hash: null, otp_exp: 0, otp_tries: 0 });
      await saveUser(u);
      setSession(res, email);
      return send(res, 200, { ok: true, name: u.name });
    }
    // login
    if (!u || !checkPw(String(b.password || ''), u.pass)) return fail(res, 'Email or password is incorrect.', 401);
    if (!u.verified) {
      const err = await sendOtp(u);
      return err ? fail(res, err, 429) : send(res, 200, { ok: true, needs_verify: true });
    }
    setSession(res, email);
    return send(res, 200, { ok: true, verified: true, name: u.name });
  } catch (e) {
    console.error(e);
    return fail(res, 'Server error. Please try again.', 500);
  }
};
