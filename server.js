const express = require('express');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// ============================================================
// ====================== CONFIGURAÇÕES =======================
// ============================================================
const DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1550274953092268122/FSFIL0HInyozWv2wdWIMwh0e54taYrVFjjLm9QcCaMZyE-TtUOrk2hPXaHkopgZLgP2j";
const APK_URL = "https://www.mediafire.com/file/ogry5nqdr2c1vpd/SHOPICA.apk/file";
const FIREBASE_DB_URL = "https://loja-do-dag-default-rtdb.firebaseio.com";

// ============================================================
// ====================== ESTADO GLOBAL =======================
// ============================================================
const sessionKeys   = new Map();
const sessionTokens = new Map();
const keyCache      = new Map();
const CACHE_TTL     = 1000;

// ============================================================
// ====================== UTILITÁRIOS =========================
// ============================================================
function getClientIp(req) {
  let ip = req.headers['cf-connecting-ip'] ||
           req.headers['x-forwarded-for'] ||
           req.headers['x-real-ip'] ||
           req.socket.remoteAddress || '';
  if (typeof ip === 'string' && ip.includes(',')) ip = ip.split(',')[0].trim();
  if (typeof ip === 'string' && ip.includes('::ffff:')) ip = ip.replace('::ffff:', '');
  return (ip || '').trim();
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx > -1) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}

function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`);
}

function createSessionToken(key, ip) {
  const token = crypto.randomBytes(24).toString('hex');
  sessionTokens.set(token, { key, ip, createdAt: Date.now() });
  return token;
}

function getSession(req) {
  const cookies = parseCookies(req);
  if (cookies.session && sessionTokens.has(cookies.session)) {
    return { ...sessionTokens.get(cookies.session), token: cookies.session };
  }
  const ip = getClientIp(req);
  if (sessionKeys.has(ip)) return { key: sessionKeys.get(ip), ip, token: null };
  return null;
}

function destroySession(req) {
  const cookies = parseCookies(req);
  if (cookies.session) sessionTokens.delete(cookies.session);
  const ip = getClientIp(req);
  sessionKeys.delete(ip);
}

// ============================================================
// ====================== FIREBASE ============================
// ============================================================
function fbRequest(method, path, bodyData) {
  return new Promise((resolve) => {
    let urlData;
    try { urlData = new URL(`${FIREBASE_DB_URL}${path}.json`); }
    catch (e) { return resolve({ ok: false, error: 'url_invalida' }); }

    const dataString = bodyData !== undefined ? JSON.stringify(bodyData) : null;
    const headers = {};
    if (dataString !== null) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(dataString);
    }
    const options = { hostname: urlData.hostname, path: urlData.pathname + urlData.search, method, headers, timeout: 10000 };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        let parsed = null;
        try { parsed = data ? JSON.parse(data) : null; } catch (e) { parsed = data; }
        resolve({ ok, statusCode: res.statusCode, data: parsed });
      });
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    if (dataString !== null) req.write(dataString);
    req.end();
  });
}

async function firebaseGet(path) {
  const r = await fbRequest('GET', path);
  if (!r.ok) return null;
  if (r.data === null || r.data === 'null') return null;
  return r.data;
}

async function firebasePatch(path, bodyData) {
  return await fbRequest('PATCH', path, bodyData);
}

// ============================================================
// ====================== HELPERS DE KEY ======================
// ============================================================
function normalizeStatus(s) { return String(s || '').toLowerCase().trim(); }
function toNumber(v, def = 0) { const n = Number(v); return Number.isFinite(n) ? n : def; }
function invalidateKeyCache(key) { if (key) keyCache.delete(key.trim().toUpperCase()); }

// Lógica completa de verificação e ativação com suporte a duração/expiração
async function checkKeyStatus(keyInput, clientIp, opts) {
  opts = opts || {};
  const skipDevice = !!opts.skipDeviceCheck;

  if (!keyInput) return { status: 'not_found' };
  const cleanKey = String(keyInput).trim().toUpperCase();
  const now = Date.now();

  const cached = keyCache.get(cleanKey);
  if (cached && (now - cached.timestamp < CACHE_TTL)) {
    if (!skipDevice && cached.usedByIp && cached.usedByIp !== clientIp) return { status: 'ip_locked' };
    return { status: cached.status };
  }

  let keyData = await firebaseGet(`/proxyAndroid/keys/${cleanKey}`);
  if (!keyData || typeof keyData !== 'object') {
    keyCache.set(cleanKey, { status: 'not_found', timestamp: now });
    return { status: 'not_found' };
  }

  let st = normalizeStatus(keyData.status);
  const durationMs = toNumber(keyData.durationMs, 0);
  let expiresAt = toNumber(keyData.expiresAt, 0);

  if (st === 'expired' && expiresAt <= 0) {
    await firebasePatch(`/proxyAndroid/keys/${cleanKey}`, { status: 'criada', expiresAt: null, activatedAt: null, usedByIp: null });
    keyData = await firebaseGet(`/proxyAndroid/keys/${cleanKey}`) || keyData;
    st = 'criada'; expiresAt = 0;
  }
  if (st === 'expired' && expiresAt > 0 && now <= expiresAt) {
    await firebasePatch(`/proxyAndroid/keys/${cleanKey}`, { status: 'active' });
    st = 'active';
  }
  if (st === 'paused') {
    keyCache.set(cleanKey, { status: 'paused', timestamp: now });
    return { status: 'paused' };
  }
  if (expiresAt > 0 && now > expiresAt) {
    keyCache.set(cleanKey, { status: 'expired', timestamp: now });
    return { status: 'expired' };
  }
  if (!skipDevice && keyData.usedByIp && keyData.usedByIp !== clientIp) {
    keyCache.set(cleanKey, { status: 'ip_locked', timestamp: now, usedByIp: keyData.usedByIp });
    return { status: 'ip_locked' };
  }
  if (st === 'active' || st === 'criada') {
    const updatePayload = {};
    if (st === 'criada') {
      updatePayload.status = 'active';
      updatePayload.activatedAt = now;
      if (durationMs > 0) updatePayload.expiresAt = now + durationMs;
    } else if (st === 'active' && expiresAt <= 0 && durationMs > 0) {
      updatePayload.expiresAt = now + durationMs;
      if (!keyData.activatedAt) updatePayload.activatedAt = now;
    }
    if (!keyData.usedByIp) updatePayload.usedByIp = clientIp;
    if (Object.keys(updatePayload).length > 0) {
      await firebasePatch(`/proxyAndroid/keys/${cleanKey}`, updatePayload);
    }
    keyCache.set(cleanKey, { status: 'active', timestamp: now, usedByIp: keyData.usedByIp || clientIp });
    return { status: 'active' };
  }
  keyCache.set(cleanKey, { status: 'not_found', timestamp: now });
  return { status: 'not_found' };
}

// ============================================================
// ====================== GEO / DISCORD =======================
// ============================================================
function getGeoInfo(ip) {
  return new Promise((resolve) => {
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168') || ip.startsWith('10.')) return resolve(null);
    const url = `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query`;
    http.get(url, (res) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { resolve(null); } });
    }).on('error', () => resolve(null));
  });
}

function sendDiscordWebhook(payload) {
  return new Promise((resolve) => {
    const data = JSON.stringify(payload);
    const urlData = new URL(DISCORD_WEBHOOK_URL);
    const options = { hostname: urlData.hostname, path: urlData.pathname + urlData.search, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } };
    const req = https.request(options, (res) => { res.on('data', () => {}); res.on('end', () => resolve(true)); });
    req.on('error', () => resolve(false));
    req.write(data); req.end();
  });
}

async function notifyDiscordLogin(req, key, clientIp, gpsData) {
  try {
    const geo = await getGeoInfo(clientIp);
    const dataHora = new Date().toLocaleString('pt-BR', { timeZone: 'America/Manaus' });
    let localStr = 'Não disponível';
    if (geo && geo.status === 'success') {
      localStr = (geo.city || '-') + ' / ' + (geo.regionName || '-') + ' / ' + (geo.country || '-');
    }
    const fields = [
      { name: "🔑 Key Utilizada", value: "`" + key + "`", inline: false },
      { name: "🌐 IP", value: "`" + clientIp + "`", inline: true },
      { name: "🕒 Data/Hora", value: "`" + dataHora + "`", inline: true },
      { name: "📍 Localização", value: localStr, inline: false }
    ];
    const embed = {
      username: "SECURE PANEL • LOGS",
      embeds: [{ title: "🔓 NOVO LOGIN AUTORIZADO", color: 0x22c55e, fields, timestamp: new Date().toISOString() }]
    };
    await sendDiscordWebhook(embed);
  } catch (e) { console.log('Erro webhook:', e.message); }
}

// ============================================================
// ====================== CSS & UI PROFISSIONAL ===============
// ============================================================
const BASE_CSS = `
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#050505;color:#f4f4f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;overflow-x:hidden;}
@keyframes auroraShift{0%{transform:translate(0,0) scale(1);}50%{transform:translate(3%,-3%) scale(1.08);}100%{transform:translate(0,0) scale(1);}}
@keyframes borderFlow{0%{background-position:0% 50%;}50%{background-position:100% 50%;}100%{background-position:0% 50%;}}
@keyframes floatY{0%,100%{transform:translateY(0);}50%{transform:translateY(-6px);}}
@keyframes fadeInScale{from{opacity:0;transform:scale(.95);}to{opacity:1;transform:scale(1);}}
.bg-aurora{position:fixed;inset:-10%;z-index:0;pointer-events:none;opacity:.85;background:radial-gradient(circle at 15% 20%,rgba(220,38,38,.28) 0%,transparent 40%),radial-gradient(circle at 85% 80%,rgba(153,27,27,.22) 0%,transparent 40%),radial-gradient(circle at 50% 50%,rgba(120,0,0,.15) 0%,transparent 55%);animation:auroraShift 14s ease-in-out infinite;}
.wrap{width:100%;max-width:430px;position:relative;z-index:2;animation:fadeInScale .6s cubic-bezier(.4,0,.2,1);}
.card{position:relative;background:linear-gradient(170deg,#0f0f14 0%,#0a0a0f 100%);border:1px solid rgba(255,255,255,.07);border-radius:24px;padding:38px 30px 28px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.9),0 0 60px -20px rgba(220,38,38,.4);overflow:hidden;}
.card::before{content:'';position:absolute;top:0;left:15%;right:15%;height:1.5px;background:linear-gradient(90deg,transparent,#ef4444 20%,#f87171 50%,#ef4444 80%,transparent);background-size:200% 100%;animation:borderFlow 4s linear infinite;}
.logo-icon{width:70px;height:70px;margin:0 auto 15px;border-radius:20px;background:linear-gradient(160deg,#1a1a20,#0a0a0e);border:1px solid rgba(239,68,68,.4);display:flex;align-items:center;justify-content:center;box-shadow:0 15px 35px -10px rgba(220,38,38,.6);animation:floatY 4s ease-in-out infinite;}
.brand{font-size:24px;font-weight:900;text-align:center;color:#fff;letter-spacing:-.5px;}
.brand b{color:#ef4444;text-shadow:0 0 12px rgba(239,68,68,.6);}
.sub{text-align:center;color:#7a7a85;font-size:12px;margin-top:6px;margin-bottom:20px;}
.input{width:100%;height:54px;padding:0 18px;border-radius:14px;background:#08080c;border:1.5px solid rgba(255,255,255,.08);color:#fff;font-size:14px;font-family:monospace;outline:none;transition:all .3s;}
.input:focus{border-color:#ef4444;box-shadow:0 0 0 4px rgba(239,68,68,.15),0 0 25px rgba(239,68,68,.4);}
.btn{width:100%;height:54px;margin-top:16px;border-radius:14px;background:linear-gradient(180deg,#ef4444,#dc2626);color:#fff;font-weight:900;text-transform:uppercase;letter-spacing:1.5px;cursor:pointer;box-shadow:0 10px 25px -8px rgba(239,68,68,.8);transition:all .3s;}
.btn:hover{filter:brightness(1.1);transform:translateY(-2px);box-shadow:0 15px 30px -8px rgba(239,68,68,1);}
.error{margin-top:14px;padding:12px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;border-radius:12px;text-align:center;font-size:12px;font-weight:bold;}
.panel-card{background:linear-gradient(170deg,#0e1310 0%,#080a09 100%);box-shadow:0 25px 50px -12px rgba(0,0,0,0.9),0 0 60px -20px rgba(34,197,94,.4);}
.panel-card::before{background:linear-gradient(90deg,transparent,#22c55e 20%,#4ade80 50%,#22c55e 80%,transparent);background-size:200% 100%;animation:borderFlow 4s linear infinite;}
.btn-green{width:100%;height:56px;margin-top:18px;border-radius:14px;background:linear-gradient(180deg,#22c55e,#16a34a);color:#fff;font-weight:900;text-transform:uppercase;letter-spacing:1.5px;cursor:pointer;box-shadow:0 10px 25px -8px rgba(34,197,94,.8);transition:all .3s;}
.btn-green:hover{filter:brightness(1.1);transform:translateY(-2px);box-shadow:0 15px 30px -8px rgba(34,197,94,1);}
.btn-logout{width:100%;height:46px;margin-top:12px;border-radius:12px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);color:#fca5a5;font-weight:800;text-transform:uppercase;letter-spacing:1px;cursor:pointer;transition:all .2s;}
.btn-logout:hover{background:rgba(239,68,68,.25);color:#fff;}
`;

// ============================================================
// ====================== ROTAS ===============================
// ============================================================
app.get('/check-status', async (req, res) => {
  const clientIp = getClientIp(req);
  const sess = getSession(req);
  if (!sess || !sess.key) return res.json({ active: false, reason: 'expired' });
  const check = await checkKeyStatus(sess.key, clientIp, { skipDeviceCheck: true });
  if (check.status === 'active') return res.json({ active: true });
  destroySession(req);
  return res.json({ active: false, reason: check.status });
});

app.get('/', async (req, res) => {
  const clientIp = getClientIp(req);
  const sess = getSession(req);
  let isAuthorized = false;
  if (sess && sess.key) {
    const check = await checkKeyStatus(sess.key, clientIp);
    if (check.status === 'active') isAuthorized = true;
    else destroySession(req);
  }

  let errorAlert = '';
  const errType = req.query.erro;
  if (errType === 'paused') errorAlert = '<div class="error">Key pausada! Acesso negado.</div>';
  else if (errType === 'expired') errorAlert = '<div class="error">Sua key expirou.</div>';
  else if (errType === 'invalid') errorAlert = '<div class="error">Key incorreta ou inválida!</div>';

  if (!isAuthorized) {
    res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secure Panel • Login</title><style>${BASE_CSS}</style></head><body>
      <div class="bg-aurora"></div>
      <div class="wrap"><div class="card">
        <div class="logo-icon">🔒</div>
        <div class="brand">SECURE <b>PANEL</b></div>
        <div class="sub">Insira sua chave de acesso</div>
        ${errorAlert}
        <form action="/login" method="POST">
          <input class="input" type="text" name="key" placeholder="XXXX-XXXX-XXXX" autocomplete="off" required>
          <button class="btn" type="submit">🔓 Desbloquear Acesso</button>
        </form>
      </div></div>
    </body></html>`);
  } else {
    res.send(`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secure Panel • Painel</title><style>${BASE_CSS}</style></head><body>
      <div class="bg-aurora" style="background:radial-gradient(circle at 15% 20%, rgba(34,197,94,.22) 0%, transparent 40%), radial-gradient(circle at 85% 80%, rgba(21,128,61,.18) 0%, transparent 40%);"></div>
      <div class="wrap"><div class="card panel-card">
        <div class="logo-icon" style="border-color:rgba(34,197,94,.4);box-shadow:0 15px 35px -10px rgba(34,197,94,.6);">📱</div>
        <div class="brand" style="color:#d1fadf;">BAIXAR <b>APLICATIVO</b></div>
        <div class="sub" style="color:#7a9a86;">Sua chave está autenticada com sucesso</div>
        <button class="btn-green" onclick="window.open('${APK_URL}','_blank')">⬇️ Baixar APK Agora</button>
        <form method="POST" action="/logout"><button class="btn-logout" type="submit">🚪 Sair / Trocar Key</button></form>
      </div></div>
    </body></html>`);
  }
});

app.post('/logout', (req, res) => {
  destroySession(req);
  res.redirect('/');
});

app.post('/login', async (req, res) => {
  const { key } = req.body;
  const clientIp = getClientIp(req);
  if (!key) return res.redirect('/?erro=invalid');
  const cleanKey = String(key).trim().toUpperCase();
  invalidateKeyCache(cleanKey);

  const check = await checkKeyStatus(cleanKey, clientIp);
  if (check.status === 'active') {
    const token = createSessionToken(cleanKey, clientIp);
    setSessionCookie(res, token);
    sessionKeys.set(clientIp, cleanKey);
    notifyDiscordLogin(req, cleanKey, clientIp, null).catch(() => {});
    return res.redirect('/');
  } else if (check.status === 'paused') {
    return res.redirect('/?erro=paused');
  } else if (check.status === 'expired') {
    return res.redirect('/?erro=expired');
  }
  return res.redirect('/?erro=invalid');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor rodando na porta ${PORT}!`);
});
