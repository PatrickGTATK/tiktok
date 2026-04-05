/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║     TIKTOK LIVE MACRO — Servidor de Licenças (Railway)      ║
 * ║     Assinatura Ed25519 — chave privada NUNCA sai do server   ║
 * ║     Banco de dados: Supabase PostgreSQL                      ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Variáveis de ambiente OBRIGATÓRIAS no Railway:
 *   ADMIN_SECRET        → senha do painel admin
 *   SIGNING_PRIVATE_KEY → chave privada Ed25519 (gerada com gerar-chaves.js)
 *   DATABASE_URL        → connection string do Supabase
 *   PORT                → definido automaticamente pelo Railway
 *
 * ── COMO GERAR AS CHAVES ──────────────────────────────────────
 *   node gerar-chaves.js
 *   → copie a PRIVATE KEY para a variável SIGNING_PRIVATE_KEY no Railway
 *   → copie a PUBLIC KEY para a constante PUBLIC_KEY em licenseManager.js
 *
 * ── TIERS ────────────────────────────────────────────────────
 *   'basic' → LiveMacro Pro apenas
 *   'full'  → LiveMacro Pro + Arena PvP
 *
 * ── CORREÇÕES DE SEGURANÇA (v2) ──────────────────────────────────
 *  [FIX-1] Token admin via cookie HttpOnly — não mais exposto na URL
 *  [FIX-2] Escape de HTML em todo output do painel (previne XSS)
 *  [FIX-5] ADMIN_SECRET sem valor padrão — bloqueia deploy esquecido
 *  [FIX-6] Limite de tamanho nos inputs (10kb body, campos truncados)
 *  [FIX-6] Validação de range em 'days' (1–365)
 *
 * ── DEPENDÊNCIA ADICIONAL ─────────────────────────────────────
 *   npm install cookie-parser
 */

const express      = require('express');
const cookieParser = require('cookie-parser');
const crypto       = require('crypto');
const fs           = require('fs');
const path         = require('path');
const { Pool }     = require('pg');
const multer       = require('multer');

const app = express();

// [SEC-FIX] trust proxy: informa ao Express que há exatamente 1 proxy
// confiável à frente (o load balancer do Railway). Com isso req.ip resolve
// para o IP real do cliente e o header X-Forwarded-For é lido de forma segura
// (o Express descarta IPs injetados pelo cliente e usa apenas o adicionado
// pelo proxy confiável). Sem essa configuração, qualquer cliente pode forjar
// o header e bypassar o rate limit baseado em IP.
app.set('trust proxy', 1);

// [FIX-6] Limite de 10kb no body — previne flood e ataques de memória
// Nota: uploads de DLL usam multipart/form-data via multer (limite separado de 500MB)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// ── UPLOAD DE DLLs (multer) ───────────────────────────────────────
// O diretório de DLLs pode vir de variável de ambiente (Railway Volume)
// ou cair no padrão __dirname/dlls
const DLLS_DIR = process.env.DLLS_DIR || path.join(__dirname, 'dlls');
if (!fs.existsSync(DLLS_DIR)) fs.mkdirSync(DLLS_DIR, { recursive: true });

const dllStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, DLLS_DIR),
  filename:    (_req,  file, cb) => cb(null, path.basename(file.originalname)),
});

const uploadDll = multer({
  storage: dllStorage,
  limits:  { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB máximo
  fileFilter: (_req, file, cb) => {
    if (!file.originalname.toLowerCase().endsWith('.dll'))
      return cb(new Error('Apenas arquivos .dll são permitidos.'));
    cb(null, true);
  },
});

const PORT               = process.env.PORT               || 3000;
const SIGNING_PRIVATE_KEY = process.env.SIGNING_PRIVATE_KEY || null;
const DATABASE_URL        = process.env.DATABASE_URL;

// [FIX-5] ADMIN_SECRET obrigatório e sem valor padrão.
// O servidor recusa a iniciar se não estiver configurado corretamente.
const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET || ADMIN_SECRET.trim().length < 12) {
  console.error('❌ ADMIN_SECRET não configurado ou muito curto (mínimo 12 caracteres)!');
  console.error('   Configure a variável de ambiente ADMIN_SECRET no Railway.');
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL não configurado!');
  process.exit(1);
}

if (!SIGNING_PRIVATE_KEY) {
  console.error('❌ SIGNING_PRIVATE_KEY não configurado! Execute gerar-chaves.js e configure no Railway.');
  process.exit(1);
}

// Chave AES-256 usada para criptografar assets no build.
// Gerada UMA VEZ via: node obfuscate.js (ou gerar-asset-key.js)
// Cole o valor impresso no terminal como ASSET_KEY_HEX no Railway.
// NUNCA commitar o valor — fica apenas aqui no Railway e no .asset-key local (gitignored).
const ASSET_KEY_HEX = process.env.ASSET_KEY_HEX;
if (!ASSET_KEY_HEX || !/^[0-9a-f]{64}$/i.test(ASSET_KEY_HEX)) {
  console.error('❌ ASSET_KEY_HEX não configurado ou inválido (deve ser 64 hex chars = 32 bytes).');
  console.error('   Execute: node obfuscate.js --print-asset-key  e cole o valor aqui.');
  process.exit(1);
}

// Valida que a chave privada carrega corretamente na inicialização
let privateKeyObject;
try {
  privateKeyObject = crypto.createPrivateKey(SIGNING_PRIVATE_KEY);
  // Teste rápido de assinatura para garantir que funciona
  crypto.sign(null, Buffer.from('teste'), privateKeyObject);
  console.log('[CRYPTO] ✅ Chave privada Ed25519 carregada com sucesso.');
} catch (e) {
  console.error('❌ SIGNING_PRIVATE_KEY inválida:', e.message);
  process.exit(1);
}

// ── BANCO DE DADOS (PostgreSQL) ───────────────────────────────────
const pool = new Pool({
  connectionString: DATABASE_URL,
  // [SEC-FIX-A] rejectUnauthorized:true + CA pinnada do Supabase.
  // O certificado raiz "Supabase Root 2021 CA" está fixado aqui —
  // qualquer certificado não assinado por essa CA é rejeitado,
  // fechando completamente o vetor MITM.
  ssl: {
    rejectUnauthorized: true,
    ca: `-----BEGIN CERTIFICATE-----
MIIDxDCCAqygAwIBAgIUbLxMod62P2ktCiAkxnKJwtE9VPYwDQYJKoZIhvcNAQEL
BQAwazELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5l
dyBDYXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJh
c2UgUm9vdCAyMDIxIENBMB4XDTIxMDQyODEwNTY1M1oXDTMxMDQyNjEwNTY1M1ow
azELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB0RlbHdhcmUxEzARBgNVBAcMCk5ldyBD
YXN0bGUxFTATBgNVBAoMDFN1cGFiYXNlIEluYzEeMBwGA1UEAwwVU3VwYWJhc2Ug
Um9vdCAyMDIxIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQXW
QyHOB+qR2GJobCq/CBmQ40G0oDmCC3mzVnn8sv4XNeWtE5XcEL0uVih7Jo4Dkx1Q
DmGHBH1zDfgs2qXiLb6xpw/CKQPypZW1JssOTMIfQppNQ87K75Ya0p25Y3ePS2t2
GtvHxNjUV6kjOZjEn2yWEcBdpOVCUYBVFBNMB4YBHkNRDa/+S4uywAoaTWnCJLUi
cvTlHmMw6xSQQn1UfRQHk50DMCEJ7Cy1RxrZJrkXXRP3LqQL2ijJ6F4yMfh+Gyb4
O4XajoVj/+R4GwywKYrrS8PrSNtwxr5StlQO8zIQUSMiq26wM8mgELFlS/32Uclt
NaQ1xBRizkzpZct9DwIDAQABo2AwXjALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFKjX
uXY32CztkhImng4yJNUtaUYsMB8GA1UdIwQYMBaAFKjXuXY32CztkhImng4yJNUt
aUYsMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAB8spzNn+4VU
tVxbdMaX+39Z50sc7uATmus16jmmHjhIHz+l/9GlJ5KqAMOx26mPZgfzG7oneL2b
VW+WgYUkTT3XEPFWnTp2RJwQao8/tYPXWEJDc0WVQHrpmnWOFKU/d3MqBgBm5y+6
jB81TU/RG2rVerPDWP+1MMcNNy0491CTL5XQZ7JfDJJ9CCmXSdtTl4uUQnSuv/Qx
Cea13BX2ZgJc7Au30vihLhub52De4P/4gonKsNHYdbWjg7OWKwNv/zitGDVDB9Y2
CMTyZKG3XEu5Ghl1LEnI3QmEKsqaCLv12BnVjbkSeZsMnevJPs1Ye6TjjJwdik5P
o/bKiIz+Fq8=
-----END CERTIFICATE-----`,
  },
});

async function initDB() {
  // Cria tabela se não existir (com coluna tier desde o início)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      key          TEXT PRIMARY KEY,
      days         INTEGER NOT NULL DEFAULT 30,
      note         TEXT    DEFAULT '',
      tier         TEXT    NOT NULL DEFAULT 'basic',
      created_at   TIMESTAMPTZ DEFAULT NOW(),
      activated_at TIMESTAMPTZ DEFAULT NULL,
      expires_at   TIMESTAMPTZ DEFAULT NULL,
      machine_id   TEXT    DEFAULT NULL,
      revoked      BOOLEAN DEFAULT FALSE
    )
  `);

  // Migração segura: adiciona coluna tier se a tabela já existia sem ela
  await pool.query(`
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'basic'
  `);

  console.log('[DB] ✅ Tabela de licenças pronta.');
}

// ── ED25519 — ASSINAR RESPOSTA ────────────────────────────────────
// A chave privada fica APENAS aqui. O cliente só tem a chave pública
// e pode verificar a assinatura, mas NUNCA forjá-la.
function signResponse(payload) {
  const _ts     = Date.now();
  const toSign  = { ...payload, _ts };
  // Serializa com chaves ordenadas para garantir determinismo
  const message = JSON.stringify(toSign, Object.keys(toSign).sort());

  const _sig = crypto
    .sign(null, Buffer.from(message), privateKeyObject)
    .toString('base64');

  return { ...toSign, _sig };
}

// ── [FIX-2] ESCAPE DE HTML ────────────────────────────────────────
// Aplica em TODO output dinâmico do painel para prevenir XSS armazenado.
// Um atacante que criar chave com note='<script>...</script>' não consegue
// executar código no browser do admin.
function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#039;');
}

// ── HELPERS ───────────────────────────────────────────────────────
function generateKey() {
  const seg = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `TTLM-${seg()}-${seg()}-${seg()}`;
}

// ── SESSÕES ADMIN ─────────────────────────────────────────────────
const adminSessions = new Map();

function createAdminSession() {
  const token = crypto.randomBytes(24).toString('hex');
  adminSessions.set(token, Date.now());
  return token;
}

function validateAdminSession(token) {
  if (!token) return false;
  const createdAt = adminSessions.get(token);
  if (!createdAt) return false;
  if (Date.now() - createdAt > 3_600_000) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [token, createdAt] of adminSessions)
    if (now - createdAt > 3_600_000) adminSessions.delete(token);
}, 30 * 60_000);

// ── RATE LIMIT ────────────────────────────────────────────────────
const ipAttempts  = new Map();
const keyAttempts = new Map();

const RATE_WINDOW_MS   = 60_000;
const RATE_MAX_API     = 10;
const RATE_MAX_ADMIN   = 5;
const RATE_MAX_PER_KEY = 10;

function getCounter(map, id, now) {
  const rec = map.get(id) || { count: 0, firstAt: now };
  if (now - rec.firstAt > RATE_WINDOW_MS) { rec.count = 0; rec.firstAt = now; }
  rec.count++;
  map.set(id, rec);
  return rec;
}

function rateLimit(req, res, maxTries = RATE_MAX_API, keyToCheck = null) {
  // [SEC-FIX] Usa req.ip em vez de ler x-forwarded-for diretamente.
  // Com app.set('trust proxy', 1) o Express valida a cadeia de proxies e
  // entrega o IP real do cliente — sem isso um atacante envia qualquer valor
  // em x-forwarded-for e bypassa o rate limit (IP spoofing trivial).
  const ip  = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();

  const ipRec = getCounter(ipAttempts, ip, now);
  if (ipRec.count > maxTries) {
    const wait = Math.ceil((RATE_WINDOW_MS - (now - ipRec.firstAt)) / 1000);
    res.status(429).json(signResponse({ ok: false, error: `Muitas tentativas. Aguarde ${wait}s.` }));
    return false;
  }

  if (keyToCheck) {
    const keyRec = getCounter(keyAttempts, keyToCheck, now);
    if (keyRec.count > RATE_MAX_PER_KEY) {
      const wait = Math.ceil((RATE_WINDOW_MS - (now - keyRec.firstAt)) / 1000);
      res.status(429).json(signResponse({ ok: false, error: `Muitas tentativas para esta chave. Aguarde ${wait}s.` }));
      return false;
    }
  }

  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [id, rec] of ipAttempts)
    if (now - rec.firstAt > RATE_WINDOW_MS * 2) ipAttempts.delete(id);
  for (const [id, rec] of keyAttempts)
    if (now - rec.firstAt > RATE_WINDOW_MS * 2) keyAttempts.delete(id);
}, 5 * 60_000);

// ── ROTA: ATIVAR (/activate) ──────────────────────────────────────
app.post('/activate', async (req, res) => {
  // [FIX-6] Trunca inputs para evitar payloads abusivos
  const cleanKey   = ((req.body?.key  || '').trim().toUpperCase()).slice(0, 32);
  const machineId  = ((req.body?.machineId || '')).slice(0, 64);

  if (!rateLimit(req, res, RATE_MAX_API, cleanKey)) return;

  if (!cleanKey || !machineId)
    return res.json(signResponse({ ok: false, error: 'Dados incompletos.' }));

  try {
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [cleanKey]);
    const entry = rows[0];

    if (!entry)
      return res.json(signResponse({ ok: false, error: 'Chave inválida ou não encontrada.' }));

    if (entry.revoked)
      return res.json(signResponse({ ok: false, error: 'Esta chave foi revogada.' }));

    if (entry.machine_id && entry.machine_id !== machineId)
      return res.json(signResponse({ ok: false, error: 'Esta chave já está ativada em outro computador.' }));

    // Primeira ativação
    if (!entry.activated_at) {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + (entry.days || 30));

      await pool.query(
        'UPDATE licenses SET activated_at = NOW(), expires_at = $1, machine_id = $2 WHERE key = $3',
        [expiresAt.toISOString(), machineId, cleanKey]
      );

      entry.expires_at = expiresAt.toISOString();
      console.log(`[ACTIVATE] ✅ ${cleanKey} — tier: ${entry.tier} — máquina ${machineId.slice(0, 8)}...`);
    }

    if (new Date() > new Date(entry.expires_at))
      return res.json(signResponse({ ok: false, error: 'Esta chave expirou.', expired: true }));

    // Retorna tier — o cliente usa isso para liberar ou não o Arena PvP
    return res.json(signResponse({ ok: true, expiresAt: entry.expires_at, tier: entry.tier || 'basic' }));

  } catch (e) {
    console.error('[ACTIVATE] Erro:', e.message);
    return res.json(signResponse({ ok: false, error: 'Erro interno do servidor.' }));
  }
});

// ── ROTA: VERIFICAR (/verify) ─────────────────────────────────────
app.post('/verify', async (req, res) => {
  // [FIX-6] Trunca inputs para evitar payloads abusivos
  const cleanKey  = ((req.body?.key || '').trim().toUpperCase()).slice(0, 32);
  const machineId = ((req.body?.machineId || '')).slice(0, 64);

  if (!rateLimit(req, res, RATE_MAX_API, cleanKey)) return;

  if (!cleanKey || !machineId)
    return res.json(signResponse({ ok: false, error: 'Dados incompletos.' }));

  try {
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [cleanKey]);
    const entry = rows[0];

    if (!entry || !entry.activated_at)
      return res.json(signResponse({ ok: false, error: 'Chave não encontrada.' }));

    if (entry.revoked)
      return res.json(signResponse({ ok: false, revoked: true, error: 'Chave revogada.' }));

    if (entry.machine_id !== machineId)
      return res.json(signResponse({ ok: false, error: 'Máquina não autorizada.' }));

    if (new Date() > new Date(entry.expires_at))
      return res.json(signResponse({ ok: false, expired: true, error: 'Licença expirada.' }));

    console.log(`[VERIFY] ✅ ${cleanKey} — tier: ${entry.tier} — máquina ${machineId.slice(0, 8)}...`);
    // Sempre retorna o tier atual do banco — se você fizer upgrade de uma chave,
    // o cliente recebe o novo tier automaticamente na próxima verificação.
    return res.json(signResponse({ ok: true, expiresAt: entry.expires_at, tier: entry.tier || 'basic' }));

  } catch (e) {
    console.error('[VERIFY] Erro:', e.message);
    return res.json(signResponse({ ok: false, error: 'Erro interno do servidor.' }));
  }
});

// ── ADMIN: LOGIN ──────────────────────────────────────────────────
// [FIX-1] Token agora vai como cookie HttpOnly/Secure — nunca aparece
//         na URL, em logs do servidor, ou no header Referer.
app.post('/admin/login', (req, res) => {
  if (!rateLimit(req, res, RATE_MAX_ADMIN)) return;

  const secret = req.body?.secret;
  if (!secret || secret !== ADMIN_SECRET) {
    console.warn(`[ADMIN] ❌ Login inválido — IP: ${req.headers['x-forwarded-for'] || req.socket.remoteAddress}`);
    return res.status(403).send(renderLoginPage('❌ Senha incorreta'));
  }

  const token = createAdminSession();
  console.log(`[ADMIN] ✅ Login — IP: ${req.headers['x-forwarded-for'] || req.socket.remoteAddress}`);

  // [FIX-1] Cookie HttpOnly + Secure + SameSite=Strict
  // HttpOnly  → JavaScript da página não consegue ler o token
  // Secure    → só enviado em HTTPS (Railway sempre usa HTTPS)
  // SameSite  → bloqueia CSRF — cookie não é enviado de outros domínios
  res.cookie('adm_session', token, {
    httpOnly: true,
    secure:   true,
    sameSite: 'Strict',
    maxAge:   3_600_000, // 1 hora em ms
  });

  return res.redirect('/admin');
});

// ── MIDDLEWARE: verificar sessão admin ────────────────────────────
// [FIX-1] Lê token do cookie (não mais da URL ou do body)
function requireAdminSession(req, res, next) {
  const token = req.cookies?.adm_session;
  if (!validateAdminSession(token)) {
    return res.redirect('/admin/login-page');
  }
  next();
}

// Página de login
app.get('/admin/login-page', (req, res) => {
  res.send(renderLoginPage());
});

function renderLoginPage(errorMsg = '') {
  const errHtml = errorMsg
    ? `<div class="err">${escapeHtml(errorMsg)}</div>`
    : '';
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<title>Admin — LiveMacro Pro</title>
<style>*{box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#e0e0e0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:32px;min-width:320px;text-align:center}
h2{color:#FFBE0B;margin-bottom:16px}p{color:#666;font-size:13px;margin-bottom:20px}
input{background:#0d1117;border:1px solid #30363d;color:#e0e0e0;padding:10px 14px;border-radius:8px;width:100%;margin-bottom:12px;font-size:14px}
button{background:linear-gradient(135deg,#FF006E,#8338EC);color:#fff;border:none;padding:10px 24px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:700;width:100%}
.err{color:#FF006E;font-size:13px;margin-bottom:12px}
</style></head><body>
<div class="box"><h2>⚡ LiveMacro Pro Admin</h2>
<p>Faça login para acessar o painel</p>
${errHtml}
<form method="POST" action="/admin/login">
<input type="password" name="secret" placeholder="Senha admin" autofocus/>
<button type="submit">Entrar</button>
</form></div></body></html>`;
}

// Redireciona /admin sem sessão válida para o login
app.get('/admin', requireAdminSession, async (req, res) => {
  try {
    const { rows: keys } = await pool.query('SELECT * FROM licenses ORDER BY created_at DESC');
    const now = new Date();

    const rows = keys.map(k => {
      const exp       = k.expires_at ? new Date(k.expires_at).toLocaleDateString('pt-BR') : '—';
      const active    = k.activated_at && !k.revoked && now < new Date(k.expires_at || 0);
      const status    = k.revoked ? '🚫 Revogada' : !k.activated_at ? '⏳ Não ativada' : !active ? '❌ Expirada' : '✅ Ativa';
      const rowColor  = k.revoked ? '#2a1a1a' : !k.activated_at ? '#1a1a2a' : !active ? '#2a1f1a' : '#1a2a1a';
      // [FIX-2] Escapamos key e note antes de inserir no HTML
      const safeKey   = escapeHtml(k.key);
      const safeNote  = escapeHtml(k.note) || '—';
      const safeMachine = k.machine_id ? escapeHtml(k.machine_id.slice(0, 8)) + '...' : '—';
      const tierBadge = k.tier === 'full'
        ? '<span style="background:#8338EC;color:#fff;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:700">FULL</span>'
        : '<span style="background:#333;color:#aaa;padding:1px 7px;border-radius:10px;font-size:10px">basic</span>';

      // [FIX-1] Forms não precisam mais carregar token oculto — autenticação
      //         é feita automaticamente pelo cookie HttpOnly em cada request.
      return `<tr style="background:${rowColor}">
        <td style="font-family:monospace;font-size:13px">${safeKey}</td>
        <td>${safeNote}</td>
        <td style="text-align:center">${k.days}d</td>
        <td style="text-align:center">${tierBadge}</td>
        <td>${status}</td>
        <td style="text-align:center">${exp}</td>
        <td style="font-family:monospace;font-size:11px">${safeMachine}</td>
        <td>
          <form method="POST" action="/admin/extend-key" style="display:inline">
            <input type="hidden" name="key" value="${safeKey}"/>
            <input type="number" name="days" value="30" min="1" max="365" style="width:50px;background:#111;color:#ccc;border:1px solid #333;padding:2px 4px;border-radius:4px"/>
            <button type="submit" style="background:#3A86FF;color:#fff;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px">+dias</button>
          </form>
          <form method="POST" action="/admin/set-tier" style="display:inline;margin-left:4px">
            <input type="hidden" name="key" value="${safeKey}"/>
            <select name="tier" style="background:#111;color:#ccc;border:1px solid #333;padding:2px 4px;border-radius:4px;font-size:11px">
              <option value="basic" ${k.tier === 'basic' ? 'selected' : ''}>basic</option>
              <option value="full"  ${k.tier === 'full'  ? 'selected' : ''}>full</option>
            </select>
            <button type="submit" style="background:#8338EC;color:#fff;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px">tier</button>
          </form>
          <form method="POST" action="/admin/reset-machine" style="display:inline;margin-left:4px">
            <input type="hidden" name="key" value="${safeKey}"/>
            <button type="submit" style="background:#FFBE0B;color:#000;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px">reset PC</button>
          </form>
          <form method="POST" action="/admin/revoke-key" style="display:inline;margin-left:4px" onsubmit="return confirm('Revogar ${safeKey}?')">
            <input type="hidden" name="key" value="${safeKey}"/>
            <button type="submit" style="background:#FF006E;color:#fff;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px">revogar</button>
          </form>
        </td>
      </tr>`;
    }).join('');

    const total  = keys.length;
    const ativas = keys.filter(k => k.activated_at && !k.revoked && now < new Date(k.expires_at || 0)).length;
    const naAtiv = keys.filter(k => !k.activated_at).length;
    const revog  = keys.filter(k => k.revoked).length;
    const expir  = keys.filter(k => k.activated_at && !k.revoked && now >= new Date(k.expires_at || 0)).length;
    const full   = keys.filter(k => k.tier === 'full').length;

    // ── DLLs disponíveis no servidor ──────────────────────────────
    let dllsHtml = '';
    try {
      const dlls = fs.existsSync(DLLS_DIR)
        ? fs.readdirSync(DLLS_DIR).filter(f => f.endsWith('.dll'))
        : [];
      if (dlls.length === 0) {
        dllsHtml = '<p style="color:#666;font-size:13px;margin:0">Nenhuma DLL no servidor ainda.</p>';
      } else {
        dllsHtml = dlls.map(dll => {
          const safeDll = escapeHtml(dll);
          const sizeMB  = (fs.statSync(path.join(DLLS_DIR, dll)).size / 1024 / 1024).toFixed(2);
          return `<div style="padding:8px 0;border-bottom:1px solid #21262d">
            <span style="font-family:monospace;font-size:13px">📦 ${safeDll} <span style="color:#555;font-size:11px">(${sizeMB} MB)</span></span>
          </div>`;
        }).join('');
      }
    } catch (e) {
      dllsHtml = `<p style="color:#FF006E;font-size:13px">Erro ao listar DLLs: ${escapeHtml(e.message)}</p>`;
    }

    res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<title>Admin — LiveMacro Pro</title>
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
.crypto-badge{background:#0a1f0a;border:1px solid #1a4a1a;color:#06D6A0;padding:6px 14px;border-radius:8px;font-size:11px;font-family:monospace;margin-bottom:20px;display:inline-block}
.logout{float:right;background:#333;color:#ccc;border:none;padding:6px 14px;border-radius:8px;cursor:pointer;font-size:12px;text-decoration:none}
</style></head><body>
<h1>⚡ LiveMacro Pro <a href="/admin/logout" class="logout">Sair</a></h1>
<div class="sub">Painel de Licenças · ${new Date().toLocaleString('pt-BR')}</div>
<div class="crypto-badge">🔐 Assinatura Ed25519 ativa — chave privada segura no servidor</div>

<div class="stats">
  <div class="stat"><b>${total}</b><span>Total</span></div>
  <div class="stat"><b style="color:#06D6A0">${ativas}</b><span>Ativas</span></div>
  <div class="stat"><b style="color:#555">${naAtiv}</b><span>Não ativadas</span></div>
  <div class="stat"><b style="color:#FF006E">${revog}</b><span>Revogadas</span></div>
  <div class="stat"><b style="color:#FFBE0B">${expir}</b><span>Expiradas</span></div>
  <div class="stat"><b style="color:#8338EC">${full}</b><span>Tier Full</span></div>
</div>

<div class="card">
  <h3>📦 DLLs no Servidor</h3>
  <div id="dll-list">${dllsHtml}</div>
</div>

<div class="card">
  <h3>➕ Criar Nova Chave</h3>
  <form method="POST" action="/admin/create-key">
    <input name="note" placeholder="Nome do cliente" style="width:200px"/>
    <input name="days" type="number" value="30" min="1" max="365" style="width:70px"/> dias
    <select name="tier" style="margin-right:6px">
      <option value="basic">basic (LiveMacro Pro)</option>
      <option value="full">full (+ Arena PvP)</option>
    </select>
    <input name="key" placeholder="TTLM-XXXX-XXXX-XXXX (vazio = gerar)" style="width:230px"/>
    <button type="submit">Criar Chave</button>
  </form>
</div>

<div class="card">
  <h3>🔑 Chaves Cadastradas</h3>
  <table>
    <tr><th>Chave</th><th>Cliente</th><th>Dias</th><th>Tier</th><th>Status</th><th>Expira</th><th>Máquina</th><th>Ações</th></tr>
    ${rows || '<tr><td colspan="8" style="text-align:center;color:#555;padding:30px">Nenhuma chave cadastrada</td></tr>'}
  </table>
</div>
</body></html>`);

  } catch (e) {
    console.error('[ADMIN] Erro:', e.message);
    res.status(500).send('Erro ao carregar painel.');
  }
});

// ── ADMIN: LOGOUT ─────────────────────────────────────────────────
app.get('/admin/logout', (req, res) => {
  const token = req.cookies?.adm_session;
  if (token) adminSessions.delete(token);
  res.clearCookie('adm_session');
  res.redirect('/admin/login-page');
});

// ── ADMIN: CRIAR CHAVE ────────────────────────────────────────────
app.post('/admin/create-key', requireAdminSession, async (req, res) => {
  const { note = '', key: customKey } = req.body;
  // [FIX-6] Valida range de dias entre 1 e 365
  const days      = Math.min(Math.max(parseInt(req.body.days) || 30, 1), 365);
  const newKey    = customKey ? customKey.trim().toUpperCase().slice(0, 32) : generateKey();
  const validTier = ['basic', 'full'].includes(req.body.tier) ? req.body.tier : 'basic';

  try {
    const { rows } = await pool.query('SELECT key FROM licenses WHERE key = $1', [newKey]);
    if (rows.length > 0)
      return res.json({ ok: false, error: 'Chave já existe.' });

    await pool.query(
      'INSERT INTO licenses (key, days, note, tier) VALUES ($1, $2, $3, $4)',
      [newKey, days, note.slice(0, 200), validTier]  // note truncado a 200 chars
    );

    console.log(`[ADMIN] ✅ Chave criada: ${newKey} (${days}d — tier: ${validTier}) — ${note}`);

    const accept = req.headers['accept'] || '';
    if (accept.includes('text/html'))
      return res.redirect('/admin');

    return res.json({ ok: true, key: newKey, days, tier: validTier });

  } catch (e) {
    console.error('[CREATE-KEY] Erro:', e.message);
    return res.json({ ok: false, error: 'Erro interno.' });
  }
});

// ── ADMIN: REVOGAR CHAVE ──────────────────────────────────────────
app.post('/admin/revoke-key', requireAdminSession, async (req, res) => {
  const cleanKey = (req.body.key || '').trim().toUpperCase().slice(0, 32);

  try {
    const { rows } = await pool.query('SELECT key FROM licenses WHERE key = $1', [cleanKey]);
    if (!rows.length) return res.json({ ok: false, error: 'Chave não encontrada.' });

    await pool.query('UPDATE licenses SET revoked = TRUE WHERE key = $1', [cleanKey]);
    console.log(`[ADMIN] 🚫 Revogada: ${cleanKey}`);

    const accept = req.headers['accept'] || '';
    if (accept.includes('text/html'))
      return res.redirect('/admin');

    return res.json({ ok: true });

  } catch (e) {
    return res.json({ ok: false, error: 'Erro interno.' });
  }
});

// ── ADMIN: EXTENDER DIAS ──────────────────────────────────────────
app.post('/admin/extend-key', requireAdminSession, async (req, res) => {
  const cleanKey  = (req.body.key || '').trim().toUpperCase().slice(0, 32);
  // [FIX-6] Valida range de dias entre 1 e 365
  const extraDays = Math.min(Math.max(parseInt(req.body.days) || 30, 1), 365);

  try {
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [cleanKey]);
    if (!rows.length) return res.json({ ok: false, error: 'Chave não encontrada.' });

    const entry = rows[0];
    const base  = entry.expires_at ? new Date(entry.expires_at) : new Date();
    base.setDate(base.getDate() + extraDays);

    await pool.query(
      'UPDATE licenses SET expires_at = $1, revoked = FALSE WHERE key = $2',
      [base.toISOString(), cleanKey]
    );

    console.log(`[ADMIN] ➕ ${cleanKey} +${extraDays}d → expira ${base.toISOString()}`);

    const accept = req.headers['accept'] || '';
    if (accept.includes('text/html'))
      return res.redirect('/admin');

    return res.json({ ok: true, expiresAt: base.toISOString() });

  } catch (e) {
    return res.json({ ok: false, error: 'Erro interno.' });
  }
});

// ── ADMIN: RESETAR MÁQUINA ────────────────────────────────────────
app.post('/admin/reset-machine', requireAdminSession, async (req, res) => {
  const cleanKey = (req.body.key || '').trim().toUpperCase().slice(0, 32);

  try {
    const { rows } = await pool.query('SELECT key FROM licenses WHERE key = $1', [cleanKey]);
    if (!rows.length) return res.json({ ok: false, error: 'Chave não encontrada.' });

    await pool.query(
      'UPDATE licenses SET machine_id = NULL, activated_at = NULL, expires_at = NULL WHERE key = $1',
      [cleanKey]
    );

    console.log(`[ADMIN] 🔄 Máquina resetada: ${cleanKey}`);

    const accept = req.headers['accept'] || '';
    if (accept.includes('text/html'))
      return res.redirect('/admin');

    return res.json({ ok: true });

  } catch (e) {
    return res.json({ ok: false, error: 'Erro interno.' });
  }
});

// ── ADMIN: ALTERAR TIER ───────────────────────────────────────────
app.post('/admin/set-tier', requireAdminSession, async (req, res) => {
  const cleanKey = (req.body.key  || '').trim().toUpperCase().slice(0, 32);
  const newTier  = ['basic', 'full'].includes(req.body.tier) ? req.body.tier : 'basic';

  try {
    const { rows } = await pool.query('SELECT key FROM licenses WHERE key = $1', [cleanKey]);
    if (!rows.length) return res.json({ ok: false, error: 'Chave não encontrada.' });

    await pool.query('UPDATE licenses SET tier = $1 WHERE key = $2', [newTier, cleanKey]);
    console.log(`[ADMIN] 🔄 Tier de ${cleanKey} → ${newTier}`);

    const accept = req.headers['accept'] || '';
    if (accept.includes('text/html'))
      return res.redirect('/admin');

    return res.json({ ok: true, tier: newTier });

  } catch (e) {
    return res.json({ ok: false, error: 'Erro interno.' });
  }
});

// ── ADMIN: UPLOAD DE DLL ──────────────────────────────────────────
app.post('/admin/upload-dll', requireAdminSession, (req, res) => {
  uploadDll.single('dll')(req, res, (err) => {
    if (err) {
      console.error('[ADMIN-UPLOAD] ❌ Erro no upload:', err.message);
      return res.status(400).send(`<script>alert("Erro: ${err.message}"); history.back();</script>`);
    }

    if (!req.file) {
      return res.status(400).send('<script>alert("Nenhum arquivo enviado."); history.back();</script>');
    }

    console.log(`[ADMIN-UPLOAD] ✅ DLL enviada: ${req.file.originalname} (${(req.file.size / 1024 / 1024).toFixed(2)} MB)`);
    return res.redirect('/admin');
  });
});

// ── ADMIN: EXCLUIR DLL ────────────────────────────────────────────
app.post('/admin/delete-dll', requireAdminSession, (req, res) => {
  // [SEC] path.basename impede path traversal
  const dllName = path.basename((req.body.dllName || '').trim());

  if (!dllName || !dllName.endsWith('.dll'))
    return res.status(400).send('<script>alert("Nome de arquivo inválido."); history.back();</script>');

  const dllPath = path.join(DLLS_DIR, dllName);

  if (!fs.existsSync(dllPath))
    return res.status(404).send('<script>alert("Arquivo não encontrado."); history.back();</script>');

  try {
    fs.unlinkSync(dllPath);
    console.log(`[ADMIN-DELETE] 🗑 DLL excluída: ${dllName}`);
    return res.redirect('/admin');
  } catch (e) {
    console.error('[ADMIN-DELETE] ❌ Erro ao excluir:', e.message);
    return res.status(500).send(`<script>alert("Erro ao excluir: ${e.message}"); history.back();</script>`);
  }
});

// ── SESSION KEY — CHAVE DE ASSETS EFÊMERA ────────────────────────
// Retorna a chave AES-256 que descriptografa os assets (.enc) do cliente.
// A chave nunca fica no .asar — vive só na RAM do cliente durante a sessão.
//
// Proteções equivalentes ao /heartbeat:
//   ❶ Licença válida + não revogada + não expirada
//   ❷ machineId bate com o registrado na ativação
//   ❸ Nonce ecoado na resposta assinada (anti-replay)
//   ❹ Assinatura Ed25519 (impossível forjar sem chave privada)
//
// Sem uma session key válida os .enc são lixo binário — mesmo que alguém
// extraia o .asar completo e compreenda todo o código do cliente.
app.post('/session-key', async (req, res) => {
  if (!rateLimit(req, res, RATE_MAX_API)) return;

  const cleanKey  = (req.body.key       || '').trim().toUpperCase().slice(0, 32);
  const machineId = (req.body.machineId || '').slice(0, 64);
  const nonce     = (req.body.nonce     || '').slice(0, 128).replace(/[^a-f0-9]/gi, '');

  if (!cleanKey || !machineId || !nonce) {
    return res.status(400).json(signResponse({ ok: false, nonce: nonce || '', error: 'Parâmetros inválidos.' }));
  }

  try {
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [cleanKey]);
    const entry = rows[0];

    if (!entry || !entry.activated_at) {
      console.warn(`[SESSION-KEY] ❌ Chave não encontrada/ativada: ${cleanKey}`);
      return res.json(signResponse({ ok: false, nonce, error: 'Licença não encontrada.' }));
    }

    if (entry.revoked) {
      console.warn(`[SESSION-KEY] 🚫 Chave revogada: ${cleanKey}`);
      return res.json(signResponse({ ok: false, nonce, error: 'Licença revogada.' }));
    }

    // ❷ Verifica machineId — impede uso da chave em outra máquina
    if (entry.machine_id && entry.machine_id !== machineId) {
      console.warn(`[SESSION-KEY] 🚫 Máquina não autorizada: ${cleanKey} — esperado ${entry.machine_id.slice(0, 8)}... recebido ${machineId.slice(0, 8)}...`);
      return res.json(signResponse({ ok: false, nonce, error: 'Máquina não autorizada.' }));
    }

    if (entry.expires_at && new Date(entry.expires_at) < new Date()) {
      console.warn(`[SESSION-KEY] ⏰ Licença expirada: ${cleanKey}`);
      return res.json(signResponse({ ok: false, nonce, error: 'Licença expirada.' }));
    }

    // ✅ Licença válida — retorna a chave de assets (assinada com Ed25519 + nonce)
    // A chave é a mesma para todos os clientes válidos (gerada no build, rotacionada manualmente).
    // O nonce garante que esta resposta não pode ser reutilizada em outra sessão.
    console.log(`[SESSION-KEY] ✅ ${cleanKey} (tier: ${entry.tier}) — máquina ${machineId.slice(0, 8)}...`);
    return res.json(signResponse({
      ok:         true,
      nonce,
      sessionKey: ASSET_KEY_HEX,   // hex string — cliente converte para Buffer
      tier:       entry.tier || 'basic',
    }));

  } catch (e) {
    console.error('[SESSION-KEY] Erro interno:', e.message);
    return res.status(500).json({ ok: false, error: 'Erro interno.' });
  }
});

// ── HEARTBEAT — VALIDAÇÃO PERIÓDICA DO CLIENTE ───────────────────
// Chamado pelo server.js local a cada 30 min para confirmar que a
// licença ainda é válida. A resposta é assinada com Ed25519 e inclui
// o nonce enviado pelo cliente (previne replay attacks).
// [SEC] Verifica também o machineId — impede que uma chave vazada
// seja usada em outra máquina sem passar pelo /activate (que bloquearia).
// Um pirata não pode falsificar a resposta sem a chave privada.
app.post('/heartbeat', async (req, res) => {
  if (!rateLimit(req, res, RATE_MAX_API)) return;

  const cleanKey  = ((req.body.key || '')).trim().toUpperCase().slice(0, 32);
  const nonce     = (req.body.nonce || '').slice(0, 128).replace(/[^a-f0-9]/gi, '');
  const machineId = (req.body.machineId || '').slice(0, 64);

  if (!cleanKey || !nonce || !machineId) {
    return res.status(400).json(signResponse({ valid: false, nonce: nonce || '', error: 'Parâmetros inválidos.' }));
  }

  try {
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [cleanKey]);

    if (!rows.length) {
      console.warn(`[HEARTBEAT] ❌ Chave não encontrada: ${cleanKey}`);
      return res.json(signResponse({ valid: false, nonce, error: 'Chave não encontrada.' }));
    }

    const entry = rows[0];

    if (entry.revoked) {
      console.warn(`[HEARTBEAT] 🚫 Chave revogada: ${cleanKey}`);
      return res.json(signResponse({ valid: false, nonce, error: 'Licença revogada.' }));
    }

    if (!entry.activated_at) {
      console.warn(`[HEARTBEAT] ⚠️  Chave não ativada: ${cleanKey}`);
      return res.json(signResponse({ valid: false, nonce, error: 'Licença não ativada.' }));
    }

    // [SEC] Verifica se a máquina que bate o heartbeat é a mesma que ativou.
    // Sem essa checagem, qualquer pessoa com a chave pode usar o app em outra
    // máquina indefinidamente — o /activate bloqueia na ativação, mas o
    // heartbeat aceitava qualquer máquina mesmo após ativação vinculada.
    if (entry.machine_id && entry.machine_id !== machineId) {
      console.warn(`[HEARTBEAT] 🚫 Máquina não autorizada: ${cleanKey} — esperado ${entry.machine_id.slice(0, 8)}... recebido ${machineId.slice(0, 8)}...`);
      return res.json(signResponse({ valid: false, nonce, error: 'Máquina não autorizada.' }));
    }

    if (entry.expires_at && new Date(entry.expires_at) < new Date()) {
      console.warn(`[HEARTBEAT] ⏰ Chave expirada: ${cleanKey}`);
      return res.json(signResponse({ valid: false, nonce, error: 'Licença expirada.' }));
    }

    // ✅ Licença ativa + máquina correta — resposta assinada com nonce ecoado (anti-replay)
    // ── Session key HMAC ─────────────────────────────────────────────────
    // Derivada de: chave + machineId + data UTC de hoje.
    // Muda automaticamente a cada dia — sem necessidade de rotação manual.
    // Incluída na resposta ANTES de assinar com Ed25519 → impossível de forjar.
    // O server.js local usa esta chave para assinar cada webhook de spawn.
    // A DLL verifica o HMAC em todo comando recebido — sem ela, 0 spawns,
    // mesmo que o pirata remende CheckLicense() para retornar true.
    const _skDate  = new Date().toISOString().slice(0, 10); // "YYYY-MM-DD"
    const _skInput = `${cleanKey}:${machineId}:${_skDate}`;
    const _skHex   = crypto
      .createHmac('sha256', SIGNING_PRIVATE_KEY)
      .update(_skInput)
      .digest('hex'); // 64 chars hex = 32 bytes

    console.log(`[HEARTBEAT] ✅ ${cleanKey} (tier: ${entry.tier}) — máquina ${machineId.slice(0, 8)}...`);
    return res.json(signResponse({ valid: true, nonce, tier: entry.tier, sk: _skHex }));

  } catch (e) {
    console.error('[HEARTBEAT] Erro interno:', e.message);
    // Não assina resposta de erro interno para não revelar detalhes
    return res.status(500).json({ valid: false, error: 'Erro interno.' });
  }
});

// ── LISTAR DLLs DISPONÍVEIS (requer licença full ativa) ──────────
app.post('/list-dlls', async (req, res) => {
  const cleanKey  = ((req.body?.key || '').trim().toUpperCase()).slice(0, 32);
  const machineId = ((req.body?.machineId || '')).slice(0, 64);

  if (!rateLimit(req, res, RATE_MAX_API, cleanKey)) return;

  if (!cleanKey || !machineId)
    return res.status(400).json({ ok: false, error: 'Dados incompletos.' });

  try {
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [cleanKey]);
    const entry = rows[0];

    if (!entry || !entry.activated_at)
      return res.status(403).json({ ok: false, error: 'Chave não encontrada.' });

    if (entry.revoked)
      return res.status(403).json({ ok: false, error: 'Chave revogada.' });

    if (entry.machine_id !== machineId)
      return res.status(403).json({ ok: false, error: 'Máquina não autorizada.' });

    if (new Date() > new Date(entry.expires_at))
      return res.status(403).json({ ok: false, error: 'Licença expirada.' });

    if ((entry.tier || 'basic') !== 'full')
      return res.status(403).json({ ok: false, error: 'Requer plano Full.' });

    const dllsDir = DLLS_DIR;
    if (!fs.existsSync(dllsDir))
      return res.status(404).json({ ok: false, error: 'Pasta dlls não encontrada no servidor.' });

    const dlls = fs.readdirSync(dllsDir).filter(f => f.endsWith('.dll'));
    if (dlls.length === 0)
      return res.status(404).json({ ok: false, error: 'Nenhuma DLL disponível no servidor.' });

    console.log(`[LIST-DLL] ✅ ${cleanKey} — ${dlls.length} DLL(s): ${dlls.join(', ')}`);
    return res.json({ ok: true, dlls });

  } catch (e) {
    console.error('[LIST-DLL] Erro:', e.message);
    return res.status(500).json({ ok: false, error: 'Erro interno do servidor.' });
  }
});

// ── DOWNLOAD DA DLL (requer licença full ativa) ───────────────────
// Aceita campo opcional "dllName" no body para baixar uma DLL específica.
// Se não informado, baixa a primeira DLL disponível (compatibilidade).
app.post('/download-dll', async (req, res) => {
  const cleanKey  = ((req.body?.key || '').trim().toUpperCase()).slice(0, 32);
  const machineId = ((req.body?.machineId || '')).slice(0, 64);
  // [SEC] path.basename impede path traversal — garante apenas o nome do arquivo
  const dllName   = req.body?.dllName ? path.basename(req.body.dllName) : null;

  if (!rateLimit(req, res, RATE_MAX_API, cleanKey)) return;

  if (!cleanKey || !machineId)
    return res.status(400).json({ ok: false, error: 'Dados incompletos.' });

  try {
    const { rows } = await pool.query('SELECT * FROM licenses WHERE key = $1', [cleanKey]);
    const entry = rows[0];

    if (!entry || !entry.activated_at)
      return res.status(403).json({ ok: false, error: 'Chave não encontrada.' });

    if (entry.revoked)
      return res.status(403).json({ ok: false, error: 'Chave revogada.' });

    if (entry.machine_id !== machineId)
      return res.status(403).json({ ok: false, error: 'Máquina não autorizada.' });

    if (new Date() > new Date(entry.expires_at))
      return res.status(403).json({ ok: false, error: 'Licença expirada.' });

    if ((entry.tier || 'basic') !== 'full')
      return res.status(403).json({ ok: false, error: 'Requer plano Full.' });

    const dllsDir = DLLS_DIR;

    // Se dllName não foi informado, usa a primeira DLL da pasta (compatibilidade)
    let resolvedName = dllName;
    if (!resolvedName) {
      const available = fs.existsSync(dllsDir)
        ? fs.readdirSync(dllsDir).filter(f => f.endsWith('.dll'))
        : [];
      if (available.length === 0)
        return res.status(404).json({ ok: false, error: 'Nenhuma DLL disponível no servidor.' });
      resolvedName = available[0];
    }

    // [SEC] Só permite .dll — rejeita extensões inesperadas mesmo após basename
    if (!resolvedName.endsWith('.dll'))
      return res.status(400).json({ ok: false, error: 'Nome de arquivo inválido.' });

    const dllPath = path.join(dllsDir, resolvedName);
    if (!fs.existsSync(dllPath))
      return res.status(404).json({ ok: false, error: `Arquivo "${resolvedName}" não encontrado no servidor.` });

    console.log(`[DLL] ✅ Download autorizado — ${resolvedName} — ${cleanKey} — máquina ${machineId.slice(0, 8)}...`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${resolvedName}"`);
    fs.createReadStream(dllPath).pipe(res);

  } catch (e) {
    console.error('[DLL] Erro:', e.message);
    return res.status(500).json({ ok: false, error: 'Erro interno do servidor.' });
  }
});

// ── HEALTH CHECK ──────────────────────────────────────────────────
app.get('/', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT COUNT(*) FROM licenses');
    res.json({ status: 'ok', service: 'LiveMacro Pro License Server v4 (Ed25519)', keys: parseInt(rows[0].count) });
  } catch {
    res.json({ status: 'ok', service: 'LiveMacro Pro License Server v4 (Ed25519)', db: 'conectando...' });
  }
});

// ── INICIAR ───────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n══════════════════════════════════════`);
    console.log(`   LiveMacro Pro License Server v4 (Ed25519)`);
    console.log(`   Porta: ${PORT}`);
    console.log(`   Admin: /admin/login-page`);
    console.log(`   Criptografia: Ed25519 ✅`);

    // ── Listar DLLs disponíveis para download ──────────────────
    const dllsDir = DLLS_DIR;
    try {
      if (fs.existsSync(dllsDir)) {
        const dlls = fs.readdirSync(dllsDir).filter(f => f.endsWith('.dll'));
        console.log(`\n   DLLs disponíveis (${dllsDir}):`);
        if (dlls.length === 0) {
          console.log(`   ⚠️  Nenhuma DLL encontrada — commit a DLL no GitHub.`);
        } else {
          dlls.forEach(dll => console.log(`   ✅ ${dll}`));
        }
      } else {
        console.log(`\n   ⚠️  Pasta ${dllsDir} não existe — commit a DLL no GitHub.`);
      }
    } catch (e) {
      console.warn(`\n   ⚠️  Erro ao listar DLLs: ${e.message}`);
    }

    console.log(`══════════════════════════════════════\n`);
  });
}).catch(e => {
  console.error('❌ Erro ao conectar no banco:', e.message);
  process.exit(1);
});
