const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(DATA, 'uploads');
const USERS_FILE = path.join(DATA, 'users.json');
const MSGS_FILE = path.join(DATA, 'messages.json');
const MAX_FILE = 25 * 1024 * 1024; // 25 MB

fs.mkdirSync(UPLOADS, { recursive: true });
if (!fs.existsSync(USERS_FILE)) {
  console.error('Falta data/users.json. Ejecuta primero: node setup-users.js <u1> <c1> <u2> <c2>');
  process.exit(1);
}
const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
let messages = fs.existsSync(MSGS_FILE) ? JSON.parse(fs.readFileSync(MSGS_FILE, 'utf8')) : [];

let saveTimer = null;
function saveMessages() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(MSGS_FILE + '.tmp', JSON.stringify(messages), (err) => {
      if (!err) fs.rename(MSGS_FILE + '.tmp', MSGS_FILE, () => {});
    });
  }, 100);
}

// ---------- Sesiones ----------
const sessions = new Map(); // token -> username
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > 0) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}
function userFromReq(req) {
  const t = parseCookies(req).sid;
  return t && sessions.get(t) ? sessions.get(t) : null;
}
function checkPassword(user, pw) {
  const u = users[user];
  if (!u) return false;
  const [salt, h] = u.pass.split(':');
  const test = crypto.scryptSync(pw, salt, 64);
  return crypto.timingSafeEqual(test, Buffer.from(h, 'hex'));
}

// Limitador simple de intentos de login por IP
const attempts = new Map();
function tooMany(ip) {
  const now = Date.now();
  const a = (attempts.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  attempts.set(ip, a);
  return a.length >= 8;
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

app.post('/api/login', (req, res) => {
  const ip = req.socket.remoteAddress;
  if (tooMany(ip)) return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos.' });
  const { user, pass } = req.body || {};
  if (typeof user !== 'string' || typeof pass !== 'string' || !checkPassword(user, pass)) {
    attempts.get(ip).push(Date.now());
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, user);
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${60 * 60 * 24 * 30}`);
  res.json({ user });
});

app.post('/api/logout', (req, res) => {
  const t = parseCookies(req).sid;
  if (t) sessions.delete(t);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const u = userFromReq(req);
  if (!u) return res.status(401).json({ error: 'No autenticado' });
  res.json({ user: u, others: Object.keys(users).filter((n) => n !== u) });
});

// Subida de archivos (cuerpo crudo)
app.post('/api/upload', (req, res) => {
  const u = userFromReq(req);
  if (!u) return res.status(401).json({ error: 'No autenticado' });
  const name = path.basename(decodeURIComponent(req.headers['x-filename'] || 'archivo'));
  const id = crypto.randomBytes(12).toString('hex');
  const dest = path.join(UPLOADS, id);
  const out = fs.createWriteStream(dest);
  let size = 0;
  let aborted = false;
  req.on('data', (chunk) => {
    size += chunk.length;
    if (size > MAX_FILE && !aborted) {
      aborted = true;
      out.destroy();
      fs.unlink(dest, () => {});
      res.status(413).json({ error: 'Archivo demasiado grande (máx. 25 MB)' });
      req.destroy();
    }
  });
  req.pipe(out);
  out.on('finish', () => {
    if (aborted) return;
    const meta = { id, name, size, type: req.headers['content-type'] || 'application/octet-stream' };
    fs.writeFileSync(dest + '.meta', JSON.stringify(meta));
    res.json(meta);
  });
});

app.get('/api/file/:id', (req, res) => {
  const u = userFromReq(req);
  if (!u) return res.status(401).end();
  const id = req.params.id.replace(/[^a-f0-9]/g, '');
  const fp = path.join(UPLOADS, id);
  if (!fs.existsSync(fp) || !fs.existsSync(fp + '.meta')) return res.status(404).end();
  const meta = JSON.parse(fs.readFileSync(fp + '.meta', 'utf8'));
  const isImg = /^image\/(png|jpe?g|gif|webp)$/.test(meta.type);
  res.setHeader('Content-Type', isImg ? meta.type : 'application/octet-stream');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader(
    'Content-Disposition',
    `${isImg ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(meta.name)}`
  );
  fs.createReadStream(fp).pipe(res);
});

// Página
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ---------- WebSocket ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
const online = new Map(); // user -> Set<ws>

server.on('upgrade', (req, socket, head) => {
  const u = userFromReq(req);
  if (!u) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.user = u;
    wss.emit('connection', ws);
  });
});

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}
function broadcast(obj) {
  for (const set of online.values()) set.forEach((ws) => send(ws, obj));
}
function presence() {
  return Object.keys(users).map((n) => ({ user: n, online: online.has(n) }));
}

wss.on('connection', (ws) => {
  if (!online.has(ws.user)) online.set(ws.user, new Set());
  online.get(ws.user).add(ws);
  send(ws, { type: 'history', messages });
  broadcast({ type: 'presence', users: presence() });

  ws.on('message', (raw) => {
    let m;
    try {
      m = JSON.parse(raw);
    } catch {
      return;
    }
    if (m.type === 'msg') {
      const text = typeof m.text === 'string' ? m.text.slice(0, 8000) : '';
      const file = m.file && typeof m.file.id === 'string'
        ? { id: m.file.id.replace(/[^a-f0-9]/g, ''), name: String(m.file.name || '').slice(0, 200), type: String(m.file.type || ''), size: Number(m.file.size) || 0 }
        : null;
      if (!text.trim() && !file) return;
      const msg = { id: crypto.randomBytes(8).toString('hex'), from: ws.user, text, file, ts: Date.now() };
      messages.push(msg);
      saveMessages();
      broadcast({ type: 'msg', message: msg });
    } else if (m.type === 'typing') {
      for (const [name, set] of online) if (name !== ws.user) set.forEach((o) => send(o, { type: 'typing', user: ws.user }));
    }
  });

  ws.on('close', () => {
    const set = online.get(ws.user);
    if (set) {
      set.delete(ws);
      if (!set.size) online.delete(ws.user);
    }
    broadcast({ type: 'presence', users: presence() });
  });
});

server.listen(PORT, () => console.log(`Chat privado en http://localhost:${PORT}`));
