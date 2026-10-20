// Crea data/users.json con los DOS usuarios autorizados.
// Uso: node setup-users.js usuario1 clave1 usuario2 clave2
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const [u1, p1, u2, p2] = process.argv.slice(2);
if (!u1 || !p1 || !u2 || !p2) {
  console.log('Uso: node setup-users.js <usuario1> <clave1> <usuario2> <clave2>');
  process.exit(1);
}
if (p1.length < 8 || p2.length < 8) {
  console.log('Las claves deben tener al menos 8 caracteres.');
  process.exit(1);
}

function hash(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(pw, salt, 64).toString('hex');
  return `${salt}:${h}`;
}

const dir = path.join(__dirname, 'data');
fs.mkdirSync(dir, { recursive: true });
const users = {
  [u1]: { name: u1, pass: hash(p1) },
  [u2]: { name: u2, pass: hash(p2) },
};
fs.writeFileSync(path.join(dir, 'users.json'), JSON.stringify(users, null, 2), { mode: 0o600 });
console.log(`Usuarios creados: ${u1}, ${u2}`);
