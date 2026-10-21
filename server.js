const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const webpush = require('web-push');

const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(DATA, 'uploads');
const USERS_FILE = path.join(DATA, 'users.json');
const MSGS_FILE = path.join(DATA, 'messages.json');
const SESSIONS_FILE = path.join(DATA, 'sessions.json');
const READ_FILE = path.join(DATA, 'read.json');
const PUSH_FILE = path.join(DATA, 'push-subs.json');
const VAPID_FILE = path.join(DATA, 'vapid.json');
const MAX_FILE = 25 * 1024 * 1024; // 25 MB
const SESSION_MAX_AGE = 60 * 60 * 24 * 365 * 5; // 5 años: en la práctica, hasta que cierren sesión a mano

fs.mkdirSync(UPLOADS, { recursive: true });
if (!fs.existsSync(USERS_FILE)) {
  console.error('Falta data/users.json. Ejecuta primero: node setup-users.js <u1> <c1> <u2> <c2>');
  process.exit(1);
}
const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
let messages = fs.existsSync(MSGS_FILE) ? JSON.parse(fs.readFileSync(MSGS_FILE, 'utf8')) : [];

// ---------- Confirmación de lectura: username -> timestamp del último mensaje leído ----------
let readState = fs.existsSync(READ_FILE) ? JSON.parse(fs.readFileSync(READ_FILE, 'utf8')) : {};
let readSaveTimer = null;
function saveReadState() {
  clearTimeout(readSaveTimer);
  readSaveTimer = setTimeout(() => {
    fs.writeFile(READ_FILE + '.tmp', JSON.stringify(readState), (err) => {
      if (!err) fs.rename(READ_FILE + '.tmp', READ_FILE, () => {});
    });
  }, 100);
}

// ---------- Notificaciones push (funcionan con el navegador/pestaña cerrada) ----------
let vapid;
if (fs.existsSync(VAPID_FILE)) {
  vapid = JSON.parse(fs.readFileSync(VAPID_FILE, 'utf8'));
} else {
  vapid = webpush.generateVAPIDKeys();
  fs.writeFileSync(VAPID_FILE, JSON.stringify(vapid, null, 2), { mode: 0o600 });
}
webpush.setVapidDetails('mailto:admin@localhost', vapid.publicKey, vapid.privateKey);

let pushSubs = fs.existsSync(PUSH_FILE) ? JSON.parse(fs.readFileSync(PUSH_FILE, 'utf8')) : {}; // username -> [subscription,...]
let pushSaveTimer = null;
function savePushSubs() {
  clearTimeout(pushSaveTimer);
  pushSaveTimer = setTimeout(() => {
    fs.writeFile(PUSH_FILE + '.tmp', JSON.stringify(pushSubs), (err) => {
      if (!err) fs.rename(PUSH_FILE + '.tmp', PUSH_FILE, () => {});
    });
  }, 100);
}
function pushToUser(username, payload) {
  const subs = pushSubs[username];
  if (!subs || !subs.length) return;
  const keep = [];
  let changed = false;
  Promise.allSettled(
    subs.map((sub) =>
      webpush.sendNotification(sub, JSON.stringify(payload)).then(
        () => keep.push(sub),
        (err) => {
          changed = true;
          if (!(err.statusCode === 404 || err.statusCode === 410)) keep.push(sub); // conserva la suscripción salvo que esté muerta
        }
      )
    )
  ).then(() => {
    if (changed) {
      pushSubs[username] = keep;
      savePushSubs();
    }
  });
}

let saveTimer = null;
function saveMessages() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(MSGS_FILE + '.tmp', JSON.stringify(messages), (err) => {
      if (!err) fs.rename(MSGS_FILE + '.tmp', MSGS_FILE, () => {});
    });
  }, 100);
}

// ---------- Sesiones (persistidas a disco: sobreviven a un reinicio del servidor) ----------
const sessions = new Map(); // token -> username
if (fs.existsSync(SESSIONS_FILE)) {
  try {
    const saved = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
    for (const [token, user] of Object.entries(saved)) if (users[user]) sessions.set(token, user);
  } catch {}
}
let sessionSaveTimer = null;
function saveSessions() {
  clearTimeout(sessionSaveTimer);
  sessionSaveTimer = setTimeout(() => {
    fs.writeFile(SESSIONS_FILE + '.tmp', JSON.stringify(Object.fromEntries(sessions)), (err) => {
      if (!err) fs.rename(SESSIONS_FILE + '.tmp', SESSIONS_FILE, () => {});
    });
  }, 100);
}
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
app.use(express.static(path.join(__dirname, 'public')));

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
  saveSessions();
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_AGE}`);
  res.json({ user });
});

app.post('/api/logout', (req, res) => {
  const t = parseCookies(req).sid;
  if (t) {
    sessions.delete(t);
    saveSessions();
  }
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

app.get('/api/vapid-public-key', (req, res) => {
  const u = userFromReq(req);
  if (!u) return res.status(401).json({ error: 'No autenticado' });
  res.json({ key: vapid.publicKey });
});

app.post('/api/push-subscribe', (req, res) => {
  const u = userFromReq(req);
  if (!u) return res.status(401).json({ error: 'No autenticado' });
  const sub = req.body;
  if (!sub || typeof sub.endpoint !== 'string') return res.status(400).json({ error: 'Suscripción inválida' });
  if (!pushSubs[u]) pushSubs[u] = [];
  if (!pushSubs[u].some((s) => s.endpoint === sub.endpoint)) pushSubs[u].push(sub);
  savePushSubs();
  res.json({ ok: true });
});

app.post('/api/push-unsubscribe', (req, res) => {
  const u = userFromReq(req);
  if (!u) return res.status(401).json({ error: 'No autenticado' });
  const endpoint = req.body && req.body.endpoint;
  if (pushSubs[u]) pushSubs[u] = pushSubs[u].filter((s) => s.endpoint !== endpoint);
  savePushSubs();
  res.json({ ok: true });
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
  send(ws, { type: 'readstate', state: readState });
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
      const srcReply = m.replyTo;
      const replyTo = srcReply && typeof srcReply.id === 'string' && messages.some((x) => x.id === srcReply.id)
        ? { id: srcReply.id, from: String(srcReply.from || '').slice(0, 60), text: String(srcReply.text || '').slice(0, 300) }
        : null;
      if (!text.trim() && !file) return;
      const msg = { id: crypto.randomBytes(8).toString('hex'), from: ws.user, text, file, replyTo, ts: Date.now() };
      messages.push(msg);
      saveMessages();
      broadcast({ type: 'msg', message: msg });
      for (const name of Object.keys(users)) {
        if (name === ws.user) continue;
        pushToUser(name, {
          title: ws.user,
          body: file ? `📎 ${file.name}` : text.slice(0, 180),
          tag: 'notas-msg',
          url: '/',
        });
      }
    } else if (m.type === 'typing') {
      for (const [name, set] of online) if (name !== ws.user) set.forEach((o) => send(o, { type: 'typing', user: ws.user }));
    } else if (m.type === 'read') {
      const upto = Number(m.upto) || 0;
      if (upto > (readState[ws.user] || 0)) {
        readState[ws.user] = upto;
        saveReadState();
        broadcast({ type: 'read_update', user: ws.user, upto });
      }
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
