/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║     TIKTOK LIVE MACRO — Servidor de Licenças (Railway)      ║
 * ║     Com assinatura HMAC — respostas não podem ser falsas     ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Variáveis de ambiente OBRIGATÓRIAS no Railway:
 *   ADMIN_SECRET   → senha do painel admin  (ex: "admin-senha-forte-123")
 *   HMAC_SECRET    → chave de assinatura    (ex: gere com: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
 *   PORT           → definido automaticamente pelo Railway
 */

const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT         = process.env.PORT || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'troque-esta-senha';
const HMAC_SECRET  = process.env.HMAC_SECRET  || 'troque-esta-chave-hmac';

if (HMAC_SECRET === 'troque-esta-chave-hmac') {
  console.warn('⚠️  ATENÇÃO: HMAC_SECRET não configurado! Configure nas variáveis do Railway.');
}

// ── BANCO DE DADOS (JSON) ─────────────────────────────────────────
const DATA_FILE = path.join(__dirname, 'licenses.json');

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE))
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (e) {
    console.error('[DB] Erro ao carregar:', e.message);
  }
  return { keys: {} };
}

function saveData() {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
  catch (e) { console.error('[DB] Erro ao salvar:', e.message); }
}

let db = loadData();

// ── HMAC — ASSINAR RESPOSTA ───────────────────────────────────────
// Garante que o Electron só aceita respostas vindas deste servidor
function signResponse(payload) {
  // Ordena as chaves para garantir que a assinatura seja sempre igual
  const data = JSON.stringify(payload, Object.keys(payload).sort());
  const sig  = crypto.createHmac('sha256', HMAC_SECRET).update(data).digest('hex');
  return { ...payload, _sig: sig, _ts: Date.now() };
}

// ── HELPERS ───────────────────────────────────────────────────────
function generateKey() {
  const seg = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `TTLM-${seg()}-${seg()}-${seg()}`;
}

function adminCheck(req, res) {
  const secret = req.body?.secret || req.query?.secret;
  if (secret !== ADMIN_SECRET) {
    res.status(403).json({ ok: false, error: 'Acesso negado.' });
    return false;
  }
  return true;
}

// ── RATE LIMIT SIMPLES (anti brute-force) ─────────────────────────
const attempts = new Map(); // ip → { count, firstAt }
const RATE_WINDOW_MS  = 60_000; // 1 minuto
const RATE_MAX_TRIES  = 10;     // max 10 tentativas por minuto por IP

function rateLimit(req, res) {
  const ip  = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const rec = attempts.get(ip) || { count: 0, firstAt: now };

  if (now - rec.firstAt > RATE_WINDOW_MS) {
    rec.count = 0; rec.firstAt = now;
  }

  rec.count++;
  attempts.set(ip, rec);

  if (rec.count > RATE_MAX_TRIES) {
    const wait = Math.ceil((RATE_WINDOW_MS - (now - rec.firstAt)) / 1000);
    res.status(429).json(signResponse({ ok: false, error: `Muitas tentativas. Aguarde ${wait}s.` }));
    return false;
  }
  return true;
}

// Limpa registros antigos a cada 5 minutos
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of attempts)
    if (now - rec.firstAt > RATE_WINDOW_MS * 2) attempts.delete(ip);
}, 5 * 60_000);

// ── ROTA: ATIVAR (/activate) ──────────────────────────────────────
app.post('/activate', (req, res) => {
  if (!rateLimit(req, res)) return;

  const { key, machineId } = req.body || {};
  if (!key || !machineId)
    return res.json(signResponse({ ok: false, error: 'Dados incompletos.' }));

  const cleanKey = key.trim().toUpperCase();
  const entry    = db.keys[cleanKey];

  if (!entry)
    return res.json(signResponse({ ok: false, error: 'Chave inválida ou não encontrada.' }));

  if (entry.revoked)
    return res.json(signResponse({ ok: false, error: 'Esta chave foi revogada.' }));

  // Já ativada em outra máquina?
  if (entry.machineId && entry.machineId !== machineId)
    return res.json(signResponse({ ok: false, error: 'Esta chave já está ativada em outro computador.' }));

  // Primeira ativação — calcula expiração
  if (!entry.activatedAt) {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + (entry.days || 30));
    entry.expiresAt   = expiresAt.toISOString();
    entry.activatedAt = new Date().toISOString();
    entry.machineId   = machineId;
    saveData();
    console.log(`[ACTIVATE] ✅ ${cleanKey} ativado — ${entry.days}d — máquina ${machineId.slice(0, 8)}...`);
  }

  if (new Date() > new Date(entry.expiresAt))
    return res.json(signResponse({ ok: false, error: 'Esta chave expirou.', expired: true }));

  return res.json(signResponse({ ok: true, expiresAt: entry.expiresAt }));
});

// ── ROTA: VERIFICAR (/verify) ─────────────────────────────────────
app.post('/verify', (req, res) => {
  if (!rateLimit(req, res)) return;

  const { key, machineId } = req.body || {};
  if (!key || !machineId)
    return res.json(signResponse({ ok: false, error: 'Dados incompletos.' }));

  const cleanKey = key.trim().toUpperCase();
  const entry    = db.keys[cleanKey];

  if (!entry || !entry.activatedAt)
    return res.json(signResponse({ ok: false, error: 'Chave não encontrada.' }));

  if (entry.revoked)
    return res.json(signResponse({ ok: false, revoked: true, error: 'Chave revogada.' }));

  if (entry.machineId !== machineId)
    return res.json(signResponse({ ok: false, error: 'Máquina não autorizada.' }));

  if (new Date() > new Date(entry.expiresAt))
    return res.json(signResponse({ ok: false, expired: true, error: 'Licença expirada.' }));

  console.log(`[VERIFY] ✅ ${cleanKey} — máquina ${machineId.slice(0, 8)}...`);
  return res.json(signResponse({ ok: true, expiresAt: entry.expiresAt }));
});

// ── ADMIN: CRIAR CHAVE ────────────────────────────────────────────
app.post('/admin/create-key', (req, res) => {
  if (!adminCheck(req, res)) return;

  const { days = 30, note = '', key: customKey } = req.body;
  const newKey = customKey ? customKey.trim().toUpperCase() : generateKey();

  if (db.keys[newKey])
    return res.json({ ok: false, error: 'Chave já existe.' });

  db.keys[newKey] = {
    key: newKey, days: parseInt(days) || 30,
    createdAt: new Date().toISOString(),
    expiresAt: null, activatedAt: null, machineId: null,
    revoked: false, note,
  };

  saveData();
  console.log(`[ADMIN] ✅ Chave criada: ${newKey} (${days} dias) — ${note}`);

  // Se veio do form HTML, redireciona pro painel
  const accept = req.headers['accept'] || '';
  if (accept.includes('text/html'))
    return res.redirect(`/admin?secret=${req.body.secret}`);

  return res.json({ ok: true, key: newKey, days: parseInt(days) || 30 });
});

// ── ADMIN: REVOGAR CHAVE ──────────────────────────────────────────
app.post('/admin/revoke-key', (req, res) => {
  if (!adminCheck(req, res)) return;

  const cleanKey = (req.body.key || '').trim().toUpperCase();
  const entry = db.keys[cleanKey];
  if (!entry) return res.json({ ok: false, error: 'Chave não encontrada.' });

  entry.revoked = true;
  saveData();
  console.log(`[ADMIN] 🚫 Revogada: ${cleanKey}`);

  const accept = req.headers['accept'] || '';
  if (accept.includes('text/html'))
    return res.redirect(`/admin?secret=${req.body.secret}`);

  return res.json({ ok: true });
});

// ── ADMIN: RENOVAR / EXTENDER DIAS ───────────────────────────────
app.post('/admin/extend-key', (req, res) => {
  if (!adminCheck(req, res)) return;

  const cleanKey  = (req.body.key || '').trim().toUpperCase();
  const extraDays = parseInt(req.body.days) || 30;
  const entry = db.keys[cleanKey];
  if (!entry) return res.json({ ok: false, error: 'Chave não encontrada.' });

  const base = entry.expiresAt ? new Date(entry.expiresAt) : new Date();
  base.setDate(base.getDate() + extraDays);
  entry.expiresAt = base.toISOString();
  entry.revoked = false;
  saveData();
  console.log(`[ADMIN] ➕ ${cleanKey} extendida por ${extraDays} dias → expira ${entry.expiresAt}`);

  const accept = req.headers['accept'] || '';
  if (accept.includes('text/html'))
    return res.redirect(`/admin?secret=${req.body.secret}`);

  return res.json({ ok: true, expiresAt: entry.expiresAt });
});

// ── ADMIN: RESETAR MÁQUINA ────────────────────────────────────────
app.post('/admin/reset-machine', (req, res) => {
  if (!adminCheck(req, res)) return;

  const cleanKey = (req.body.key || '').trim().toUpperCase();
  const entry = db.keys[cleanKey];
  if (!entry) return res.json({ ok: false, error: 'Chave não encontrada.' });

  entry.machineId   = null;
  entry.activatedAt = null;
  entry.expiresAt   = null;
  saveData();
  console.log(`[ADMIN] 🔄 Máquina resetada: ${cleanKey}`);

  const accept = req.headers['accept'] || '';
  if (accept.includes('text/html'))
    return res.redirect(`/admin?secret=${req.body.secret}`);

  return res.json({ ok: true });
});

// ── ADMIN: PAINEL HTML ────────────────────────────────────────────
app.get('/admin', (req, res) => {
  if (!adminCheck(req, res)) return;

  const secret = req.query.secret;
  const keys   = Object.values(db.keys);
  const now    = new Date();

  const rows = keys.map(k => {
    const exp    = k.expiresAt ? new Date(k.expiresAt).toLocaleDateString('pt-BR') : '—';
    const active = k.activatedAt && !k.revoked && now < new Date(k.expiresAt || 0);
    const status = k.revoked ? '🚫 Revogada' : !k.activatedAt ? '⏳ Não ativada' : !active ? '❌ Expirada' : '✅ Ativa';
    const rowColor = k.revoked ? '#2a1a1a' : !k.activatedAt ? '#1a1a2a' : !active ? '#2a1f1a' : '#1a2a1a';
    return `<tr style="background:${rowColor}">
      <td style="font-family:monospace;font-size:13px">${k.key}</td>
      <td>${k.note || '—'}</td>
      <td style="text-align:center">${k.days}d</td>
      <td>${status}</td>
      <td style="text-align:center">${exp}</td>
      <td style="font-family:monospace;font-size:11px">${k.machineId ? k.machineId.slice(0,8)+'...' : '—'}</td>
      <td>
        <form method="POST" action="/admin/extend-key" style="display:inline">
          <input type="hidden" name="secret" value="${secret}"/>
          <input type="hidden" name="key" value="${k.key}"/>
          <input type="number" name="days" value="30" style="width:50px;background:#111;color:#ccc;border:1px solid #333;padding:2px 4px;border-radius:4px"/>
          <button type="submit" style="background:#3A86FF;color:#fff;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px">+dias</button>
        </form>
        <form method="POST" action="/admin/reset-machine" style="display:inline;margin-left:4px">
          <input type="hidden" name="secret" value="${secret}"/>
          <input type="hidden" name="key" value="${k.key}"/>
          <button type="submit" style="background:#FFBE0B;color:#000;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px">reset PC</button>
        </form>
        <form method="POST" action="/admin/revoke-key" style="display:inline;margin-left:4px" onsubmit="return confirm('Revogar ${k.key}?')">
          <input type="hidden" name="secret" value="${secret}"/>
          <input type="hidden" name="key" value="${k.key}"/>
          <button type="submit" style="background:#FF006E;color:#fff;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px">revogar</button>
        </form>
      </td>
    </tr>`;
  }).join('');

  const total   = keys.length;
  const ativas  = keys.filter(k => k.activatedAt && !k.revoked && now < new Date(k.expiresAt || 0)).length;
  const naAtiv  = keys.filter(k => !k.activatedAt).length;
  const revog   = keys.filter(k => k.revoked).length;
  const expir   = keys.filter(k => k.activatedAt && !k.revoked && now >= new Date(k.expiresAt || 0)).length;

  res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<title>Admin — TTLM Licenças</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#e0e0e0;padding:30px;min-height:100vh}
h1{background:linear-gradient(135deg,#FF006E,#FFBE0B);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:24px;margin-bottom:4px}
.sub{color:#555;font-size:12px;margin-bottom:24px}
.stats{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
.stat{background:#161b22;padding:14px 20px;border-radius:12px;border:1px solid #30363d;min-width:100px}
.stat b{display:block;font-size:26px;color:#FFBE0B}
.stat span{font-size:11px;color:#666}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:20px}
.card h3{color:#58a6ff;margin-bottom:14px;font-size:14px}
input,select{background:#0d1117;border:1px solid #30363d;color:#e0e0e0;padding:8px 12px;border-radius:8px;margin-right:6px;margin-bottom:6px;font-size:13px}
button[type=submit]{background:linear-gradient(135deg,#FF006E,#8338EC);color:#fff;border:none;padding:9px 18px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:700}
button[type=submit]:hover{filter:brightness(1.15)}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #21262d;font-size:12px}
th{background:#0d1117;color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
tr:hover{filter:brightness(1.2)}
</style></head><body>
<h1>⚡ TikTok Live Macro</h1>
<div class="sub">Painel de Licenças · ${new Date().toLocaleString('pt-BR')}</div>

<div class="stats">
  <div class="stat"><b>${total}</b><span>Total</span></div>
  <div class="stat"><b style="color:#06D6A0">${ativas}</b><span>Ativas</span></div>
  <div class="stat"><b style="color:#555">${naAtiv}</b><span>Não ativadas</span></div>
  <div class="stat"><b style="color:#FF006E">${revog}</b><span>Revogadas</span></div>
  <div class="stat"><b style="color:#FFBE0B">${expir}</b><span>Expiradas</span></div>
</div>

<div class="card">
  <h3>➕ Criar Nova Chave</h3>
  <form method="POST" action="/admin/create-key">
    <input type="hidden" name="secret" value="${secret}"/>
    <input name="note" placeholder="Nome do cliente" style="width:200px"/>
    <input name="days" type="number" value="30" style="width:70px"/> dias
    <input name="key" placeholder="TTLM-XXXX-XXXX-XXXX (deixe vazio pra gerar)" style="width:230px"/>
    <button type="submit">Criar Chave</button>
  </form>
</div>

<div class="card">
  <h3>🔑 Chaves Cadastradas</h3>
  <table>
    <tr><th>Chave</th><th>Cliente</th><th>Dias</th><th>Status</th><th>Expira</th><th>Máquina</th><th>Ações</th></tr>
    ${rows || '<tr><td colspan="7" style="text-align:center;color:#555;padding:30px">Nenhuma chave cadastrada</td></tr>'}
  </table>
</div>
</body></html>`);
});

// ── HEALTH CHECK ──────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'TTLM License Server v2', keys: Object.keys(db.keys).length });
});

app.listen(PORT, () => {
  console.log(`\n══════════════════════════════════════`);
  console.log(`   TTLM License Server v2 (HMAC)`);
  console.log(`   Porta: ${PORT}`);
  console.log(`   Chaves: ${Object.keys(db.keys).length}`);
  console.log(`   Admin: /admin?secret=SUA_SENHA`);
  console.log(`   HMAC: ${HMAC_SECRET !== 'troque-esta-chave-hmac' ? '✅ configurado' : '⚠️  NÃO configurado!'}`);
  console.log(`══════════════════════════════════════\n`);
});
