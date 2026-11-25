'use strict';
const express = require('express'), session = require('express-session'), PgStore = require('connect-pg-simple')(session),
  helmet = require('helmet'), rateLimit = require('express-rate-limit'), argon2 = require('argon2'),
  { Pool } = require('pg'), fs = require('fs'), path = require('path');

const prod = process.env.NODE_ENV === 'production', ADMIN = (process.env.ADMIN_USERNAME || '').trim();
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('Задайте SESSION_SECRET (минимум 32 символа) в файле .env'); process.exit(1);
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === '1' ? { rejectUnauthorized: false } : undefined }),
  H = p => argon2.hash(p, { type: argon2.argon2id }),
  LOGIN = /^[\p{L}\d_.-]{3,24}$/u, pwOk = p => typeof p === 'string' && p.length >= 8 && p.length <= 128,
  pub = u => ({ username: u.username, role: u.role, mustChangePassword: u.must_change_pw }),
  fail = (res, c, error, code) => res.status(c).json({ error, code }),
  lim = (max, min) => rateLimit({ windowMs: min * 6e4, limit: max, standardHeaders: true, legacyHeaders: false, message: { error: 'Слишком много запросов. Попробуйте позже.' } });
let DUMMY;

const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', +process.env.TRUST_PROXY);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { useDefaults: false, directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'], scriptSrcAttr: ["'unsafe-inline'"],
  styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ['https://fonts.gstatic.com'],
  imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"] } } }));
app.use(express.json({ limit: '1mb' }));
app.use(session({ store: new PgStore({ pool, createTableIfMissing: true }), name: 'ortbit.sid', secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false, rolling: true, cookie: { httpOnly: true, sameSite: 'lax', secure: prod, maxAge: 7 * 864e5 } }));
// CSRF: изменяющие запросы принимаются только с собственным заголовком (чужой сайт не может его отправить без CORS)
app.use('/api', (q, s, n) => q.method === 'GET' || q.get('x-requested-with') === 'ortbit' ? n() : fail(s, 403, 'Запрос отклонён', 'csrf'));

const startSession = (req, u) => new Promise((ok, no) => req.session.regenerate(e => {
  if (e) return no(e); req.session.uid = u.id; req.session.save(e2 => e2 ? no(e2) : ok());
}));
// userId берётся ТОЛЬКО из серверной сессии, никогда из запроса
const auth = (allowMust = false) => async (req, res, next) => {
  const id = req.session && req.session.uid; if (!id) return fail(res, 401, 'Требуется вход', 'auth');
  const { rows: [u] } = await pool.query('SELECT id,username,role,must_change_pw FROM users WHERE id=$1', [id]);
  if (!u) return req.session.destroy(() => fail(res, 401, 'Требуется вход', 'auth'));
  if (u.must_change_pw && !allowMust) return fail(res, 403, 'Сначала смените временный пароль', 'must_change_password');
  req.user = u; next();
};

app.post('/api/register', lim(10, 60), async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || !LOGIN.test(username.trim())) return fail(res, 400, 'Логин: 3–24 символа (буквы, цифры, _ . -)');
  if (!pwOk(password)) return fail(res, 400, 'Пароль должен содержать от 8 до 128 символов');
  const name = username.trim();
  if (ADMIN && name.toLowerCase() === ADMIN.toLowerCase()) return fail(res, 409, 'Этот логин уже занят');
  try { // роль всегда 'user' (значение по умолчанию в БД), поле role из запроса игнорируется
    const { rows: [u] } = await pool.query('INSERT INTO users(username,pass_hash) VALUES($1,$2) RETURNING id,username,role,must_change_pw', [name, await H(password)]);
    await startSession(req, u); res.status(201).json({ user: pub(u) });
  } catch (e) { if (e.code === '23505') return fail(res, 409, 'Этот логин уже занят'); throw e; }
});

app.post('/api/login', lim(20, 15), async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || password.length > 128 || username.length > 64) return fail(res, 400, 'Введите логин и пароль');
  const { rows: [u] } = await pool.query('SELECT * FROM users WHERE lower(username)=lower($1)', [username.trim()]);
  if (u && u.locked_until && u.locked_until > new Date()) return fail(res, 429, 'Слишком много неудачных попыток. Попробуйте через 15 минут.');
  const ok = (await argon2.verify(u ? u.pass_hash : DUMMY, password).catch(() => false)) && !!u; // одинаковое время ответа для несуществующего логина
  if (!ok) {
    if (u) await pool.query("UPDATE users SET failed_attempts=CASE WHEN failed_attempts>=4 THEN 0 ELSE failed_attempts+1 END, locked_until=CASE WHEN failed_attempts>=4 THEN now()+interval '15 minutes' ELSE locked_until END WHERE id=$1", [u.id]);
    return fail(res, 401, 'Неверный логин или пароль', 'bad_credentials');
  }
  await pool.query('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=$1', [u.id]);
  await startSession(req, u); res.json({ user: pub(u) });
});

app.post('/api/logout', (req, res) => req.session.destroy(() => { res.clearCookie('ortbit.sid'); res.json({ ok: true }); }));
app.get('/api/me', auth(true), (req, res) => res.json({ user: pub(req.user) }));

app.get('/api/state', auth(), async (req, res) => {
  const { rows: [r] } = await pool.query('SELECT data FROM user_state WHERE user_id=$1', [req.user.id]);
  res.json({ data: r ? r.data : null });
});
app.put('/api/state', auth(), async (req, res) => {
  const d = req.body && req.body.data;
  if (!d || typeof d !== 'object' || Array.isArray(d) || !Array.isArray(d.topics) || !Array.isArray(d.tests)) return fail(res, 400, 'Некорректные данные');
  await pool.query('INSERT INTO user_state(user_id,data) VALUES($1,$2) ON CONFLICT (user_id) DO UPDATE SET data=EXCLUDED.data, updated_at=now()', [req.user.id, JSON.stringify(d)]);
  res.json({ ok: true });
});

app.post('/api/password', lim(10, 15), auth(true), async (req, res) => {
  const { current, next } = req.body || {};
  if (typeof current !== 'string' || !pwOk(next)) return fail(res, 400, 'Новый пароль должен содержать от 8 до 128 символов');
  if (next === current) return fail(res, 400, 'Новый пароль должен отличаться от текущего');
  const { rows: [u] } = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
  if (!(await argon2.verify(u.pass_hash, current).catch(() => false))) return fail(res, 403, 'Текущий пароль указан неверно', 'bad_current');
  await pool.query('UPDATE users SET pass_hash=$2, must_change_pw=false WHERE id=$1', [u.id, await H(next)]);
  await pool.query("DELETE FROM session WHERE sess->>'uid'=$1", [String(u.id)]); // выход со всех устройств
  await startSession(req, u); res.json({ ok: true });
});

// Пример проверки роли на сервере: список аккаунтов без каких-либо данных о прогрессе
app.get('/api/admin/users', auth(), (q, s, n) => q.user.role === 'admin' ? n() : fail(s, 403, 'Недостаточно прав', 'forbidden'),
  async (q, s) => s.json({ users: (await pool.query('SELECT username,role,created_at FROM users ORDER BY id')).rows }));

app.use('/api', (q, s) => fail(s, 404, 'Не найдено'));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => { console.error(err); fail(res, err.status || 500, err.status && err.status < 500 ? 'Некорректный запрос' : 'Ошибка сервера'); });

(async () => {
  await pool.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
  DUMMY = await H('dummy-password');
  if (ADMIN && process.env.ADMIN_PASSWORD) { // создаётся один раз; существующий аккаунт и его пароль не перезаписываются
    await pool.query("INSERT INTO users(username,pass_hash,role,must_change_pw) VALUES($1,$2,'admin',true) ON CONFLICT DO NOTHING", [ADMIN, await H(process.env.ADMIN_PASSWORD)]);
  }
  app.listen(process.env.PORT || 3000, () => console.log('ORTBIT запущен на порту ' + (process.env.PORT || 3000)));
})().catch(e => { console.error(e); process.exit(1); });
