const express      = require('express');
const sqlite3      = require('sqlite3').verbose();
const snmp         = require('net-snmp');
const net          = require('net');
const http         = require('http');
const helmet       = require('helmet');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const crypto       = require('crypto');
const fs           = require('fs');
const path         = require('path');

const app = express();

// ── Validação de IP e campos de impressora ────────────────────────────────────
const IPV4_RE = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

function validarImpressora(body, obrigatorio = true) {
    const erros = [];
    const { nome, ip, modelo } = body;
    if (obrigatorio || nome !== undefined) {
        if (!nome || typeof nome !== 'string' || !nome.trim()) erros.push('nome é obrigatório');
    }
    if (obrigatorio || ip !== undefined) {
        if (ip !== undefined && !IPV4_RE.test(String(ip).trim())) erros.push('ip inválido (use formato IPv4)');
    }
    if (obrigatorio || modelo !== undefined) {
        if (!modelo || typeof modelo !== 'string' || !modelo.trim()) erros.push('modelo é obrigatório');
    }
    return erros;
}

function validarEstoque(body) {
    const erros = [];
    const { modelo, insumo, quantidade } = body;
    if (!modelo || typeof modelo !== 'string' || !modelo.trim()) erros.push('modelo é obrigatório');
    if (!insumo  || typeof insumo  !== 'string' || !insumo.trim())  erros.push('insumo é obrigatório');
    if (quantidade === undefined || quantidade === null) erros.push('quantidade é obrigatória');
    else if (!Number.isInteger(Number(quantidade)) || Number(quantidade) < 0) erros.push('quantidade deve ser inteiro >= 0');
    return erros;
}

// ── Tokens de estoque (memória, TTL 5 min) ────────────────────────────────────
const estoqueTokens = new Map();

function gerarTokenEstoque() {
    const token = crypto.randomBytes(24).toString('hex');
    estoqueTokens.set(token, Date.now() + 5 * 60 * 1000);
    return token;
}

function verificarTokenEstoque(req, res, next) {
    const auth  = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const exp   = estoqueTokens.get(token);
    if (!exp || Date.now() > exp) return res.status(401).json({ erro: 'Não autorizado' });
    next();
}

// Remove tokens expirados da memória a cada minuto
setInterval(() => {
    const now = Date.now();
    for (const [token, exp] of estoqueTokens) {
        if (now > exp) estoqueTokens.delete(token);
    }
}, 60_000).unref();

// ── Cache do dashboard ────────────────────────────────────────────────────────
let dashCache     = null;
let dashCacheAt   = 0;
let dashRefreshing = false;
const DASH_TTL    = 60_000;

function invalidarCacheDash() {
    dashCache = null;
    dashCacheAt = 0;
}

async function refreshDashCache(rows) {
    if (dashRefreshing) return;
    dashRefreshing = true;
    try {
        const resultados = await Promise.all(rows.map(async (imp) => {
            const snmpData = await obterDadosSNMP(imp.ip, imp.comunidade);
            return { ...imp, material: imp.material || 'Toner', tipo: imp.tipo || 'Colorido', ...snmpData };
        }));
        dashCache   = resultados;
        dashCacheAt = Date.now();
    } finally {
        dashRefreshing = false;
    }
}

// ── Credenciais de admin ──────────────────────────────────────────────────────
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
let   ADMIN_SENHA = process.env.ADMIN_SENHA;
if (!ADMIN_SENHA) {
    ADMIN_SENHA = crypto.randomBytes(8).toString('hex');
    console.warn('⚠️  ADMIN_SENHA não definida. Senha temporária gerada:', ADMIN_SENHA);
}

const adminTokens = new Map();
const PERMISSOES_PADRAO = ['dashboard', 'impressoras', 'estoque', 'relatorios', 'usuarios', 'imprimir'];

function normalizarPermissoes(valor) {
    if (!valor) return [...PERMISSOES_PADRAO];
    if (Array.isArray(valor)) return valor.filter(p => PERMISSOES_PADRAO.includes(p));
    try {
        const parsed = JSON.parse(valor);
        return Array.isArray(parsed) ? parsed.filter(p => PERMISSOES_PADRAO.includes(p)) : [...PERMISSOES_PADRAO];
    } catch {
        return String(valor).split(',').map(p => p.trim()).filter(p => PERMISSOES_PADRAO.includes(p));
    }
}

function gerarTokenAdmin(user = {}) {
    const token = crypto.randomBytes(32).toString('hex');
    const perfil = user.perfil || 'admin';
    const permissoes = perfil === 'admin' ? [...PERMISSOES_PADRAO] : normalizarPermissoes(user.permissoes);
    adminTokens.set(token, {
        exp: Date.now() + 8 * 60 * 60 * 1000,
        userId: user.id || null,
        usuario: user.usuario || ADMIN_USER,
        nome: user.nome || 'Administrador',
        perfil,
        permissoes
    });
    return token;
}

function verificarTokenAdmin(req, res, next) {
    const auth  = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const entry = adminTokens.get(token);
    const exp   = typeof entry === 'number' ? entry : entry?.exp;
    if (!exp || Date.now() > exp) return res.status(401).json({ erro: 'Não autorizado' });
    req.adminToken = token;
    req.adminUser = typeof entry === 'number'
        ? { perfil: 'admin', permissoes: [...PERMISSOES_PADRAO], usuario: ADMIN_USER }
        : entry;
    next();
}

function exigirPermissao(permissao) {
    return (req, res, next) => {
        verificarTokenAdmin(req, res, () => {
            const user = req.adminUser || {};
            const permissoes = normalizarPermissoes(user.permissoes);
            if (user.perfil === 'admin' || permissoes.includes(permissao)) return next();
            res.status(403).json({ erro: 'Acesso negado para esta função.' });
        });
    };
}

function exigirAlgumaPermissao(permissoesNecessarias) {
    return (req, res, next) => {
        verificarTokenAdmin(req, res, () => {
            const user = req.adminUser || {};
            const permissoes = normalizarPermissoes(user.permissoes);
            if (user.perfil === 'admin' || permissoesNecessarias.some(p => permissoes.includes(p))) return next();
            res.status(403).json({ erro: 'Acesso negado para esta função.' });
        });
    };
}

setInterval(() => {
    const now = Date.now();
    for (const [token, entry] of adminTokens) {
        const exp = typeof entry === 'number' ? entry : entry.exp;
        if (now > exp) adminTokens.delete(token);
    }
}, 60_000).unref();

// Tokens temporários para troca de senha obrigatória (TTL 15 min)
const tempTrocarSenhaTokens = new Map(); // token → { userId, exp }

function gerarTempToken(userId) {
    const token = crypto.randomBytes(24).toString('hex');
    tempTrocarSenhaTokens.set(token, { userId, exp: Date.now() + 15 * 60 * 1000 });
    return token;
}

setInterval(() => {
    const now = Date.now();
    for (const [token, { exp }] of tempTrocarSenhaTokens) {
        if (now > exp) tempTrocarSenhaTokens.delete(token);
    }
}, 60_000).unref();

// ── Hashing de senhas (scrypt) ────────────────────────────────────────────────
function hashSenha(senha) {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16).toString('hex');
        crypto.scrypt(senha, salt, 64, (err, hash) => {
            if (err) return reject(err);
            resolve(salt + ':' + hash.toString('hex'));
        });
    });
}

function verificarSenha(senha, armazenado) {
    return new Promise((resolve, reject) => {
        const [salt, key] = armazenado.split(':');
        crypto.scrypt(senha, salt, 64, (err, derived) => {
            if (err) return reject(err);
            resolve(derived.toString('hex') === key);
        });
    });
}

// ── Acoplamento ao Gestão (gestao-sbr) — Protocolo de Acoplamento ────────────
// JWT HS256 curto (60s) emitido pelo Gestão após o usuário já ter passado
// pelo gate `ti.monitoramento.read` lá — este produto confia no token e não
// fala com o AD. Verificação por HMAC nativo (crypto), sem lib de JWT.
// Ver docs/PROTOCOLO-DE-ACOPLAMENTO.md no repo sbrgestao.
const DOCKING_SECRET_ACOPLAMENTO = process.env.DOCKING_SECRET_MONITOR_IMPRESSORAS;
const DOCKING_PRODUTO_SLUG = 'monitor-impressoras';

function base64urlDecodeToString(str) {
    let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Buffer.from(s, 'base64').toString('utf8');
}

function verificarTokenAcoplamento(token, secret) {
    const partes = String(token || '').split('.');
    if (partes.length !== 3) return null;
    const [headerB64, payloadB64, sigB64] = partes;
    const assinaturaEsperada = crypto
        .createHmac('sha256', secret)
        .update(`${headerB64}.${payloadB64}`)
        .digest('base64url');
    const a = Buffer.from(assinaturaEsperada);
    const b = Buffer.from(sigB64);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

    let payload;
    try { payload = JSON.parse(base64urlDecodeToString(payloadB64)); } catch { return null; }
    if (!payload || typeof payload !== 'object') return null;
    if (!payload.sub || payload.produto !== DOCKING_PRODUTO_SLUG) return null;
    if (typeof payload.exp !== 'number' || Date.now() / 1000 > payload.exp) return null;
    return payload;
}

function provisionarUsuarioAcoplado(sub, nomeExibicao) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM usuarios WHERE usuario = ?', [sub], async (err, user) => {
            if (err) return reject(err);
            if (user) return resolve(user);
            try {
                // Senha aleatória e nunca comunicada — esta conta só entra via SSO.
                // Só chega aqui quem já passou pelo gate `ti.monitoramento.read` no Gestão.
                const hash = await hashSenha(crypto.randomBytes(32).toString('hex'));
                db.run(
                    `INSERT INTO usuarios (nome, usuario, senha_hash, perfil, permissoes) VALUES (?, ?, ?, 'admin', ?)`,
                    [nomeExibicao || sub, sub, hash, JSON.stringify(PERMISSOES_PADRAO)],
                    function (e) {
                        if (e) return reject(e);
                        db.get('SELECT * FROM usuarios WHERE id = ?', [this.lastID], (e2, novoUser) => {
                            if (e2) return reject(e2);
                            resolve(novoUser);
                        });
                    }
                );
            } catch (e) { reject(e); }
        });
    });
}

// ── Credencial de estoque ─────────────────────────────────────────────────────
let ESTOQUE_SENHA = process.env.ESTOQUE_SENHA;
if (!ESTOQUE_SENHA) {
    ESTOQUE_SENHA = crypto.randomBytes(16).toString('hex');
    console.warn('⚠️  ESTOQUE_SENHA não definida. Token temporário gerado para esta sessão.');
    console.warn('   Defina a variável de ambiente para acesso persistente ao estoque.');
}

// ── Banco de dados ────────────────────────────────────────────────────────────
const DB_PATH = process.env.DATABASE_PATH || './banco.db';
const db = new sqlite3.Database(DB_PATH);

const dbReady = new Promise(resolve => {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS impressoras (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT, ip TEXT, modelo TEXT, localizacao TEXT, comunidade TEXT, tipo TEXT, material TEXT
        )`);
        db.run(`ALTER TABLE impressoras ADD COLUMN material TEXT`, () => {});
        db.run(`ALTER TABLE impressoras ADD COLUMN tipo TEXT`, () => {});
        db.run(`UPDATE impressoras SET material = 'Toner' WHERE material IS NULL`);
        db.run(`UPDATE impressoras SET tipo = 'Colorido' WHERE tipo IS NULL`);
        db.run(`CREATE TABLE IF NOT EXISTS estoque (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            modelo TEXT, insumo TEXT, quantidade INTEGER, estado TEXT,
            UNIQUE(modelo, insumo, estado)
        )`);
        db.run(`
            INSERT OR REPLACE INTO estoque (modelo, insumo, quantidade, estado)
            SELECT modelo, insumo, SUM(quantidade), 'Novo'
            FROM estoque
            GROUP BY modelo, insumo
            HAVING COUNT(*) > 1
        `, () => {
            db.run(`DELETE FROM estoque WHERE estado != 'Novo' AND rowid NOT IN (
                SELECT MIN(rowid) FROM estoque GROUP BY modelo, insumo
            )`);
        });
        db.run(`CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            usuario TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            trocar_senha INTEGER DEFAULT 0,
            perfil TEXT DEFAULT 'admin',
            permissoes TEXT DEFAULT '["dashboard","impressoras","estoque","relatorios","usuarios","imprimir"]',
            ativo INTEGER DEFAULT 1,
            criado_em TEXT DEFAULT (datetime('now'))
        )`);
        db.run(`ALTER TABLE usuarios ADD COLUMN trocar_senha INTEGER DEFAULT 0`, () => {});
        db.run(`ALTER TABLE usuarios ADD COLUMN ultimo_login TEXT`, () => {});
        db.run(`ALTER TABLE usuarios ADD COLUMN perfil TEXT DEFAULT 'admin'`, () => {});
        db.run(`ALTER TABLE usuarios ADD COLUMN permissoes TEXT DEFAULT '["dashboard","impressoras","estoque","relatorios","usuarios","imprimir"]'`, () => {});
        db.run(`UPDATE usuarios SET perfil = 'admin' WHERE perfil IS NULL`);
        db.run(`UPDATE usuarios SET permissoes = '["dashboard","impressoras","estoque","relatorios","usuarios","imprimir"]' WHERE permissoes IS NULL`);
        db.run(`CREATE TABLE IF NOT EXISTS historico_paginas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            impressora_id INTEGER NOT NULL,
            paginas_total INTEGER,
            coletado_em TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (impressora_id) REFERENCES impressoras(id) ON DELETE CASCADE
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS historico_tinta (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            impressora_id INTEGER NOT NULL,
            cor TEXT NOT NULL,
            percentual INTEGER,
            coletado_em TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (impressora_id) REFERENCES impressoras(id) ON DELETE CASCADE
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS trocas_toner (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            impressora_id INTEGER NOT NULL,
            cor TEXT NOT NULL,
            percentual_anterior INTEGER,
            percentual_novo INTEGER,
            observacao TEXT,
            usuario TEXT,
            registrado_em TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (impressora_id) REFERENCES impressoras(id) ON DELETE CASCADE
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS historico_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            impressora_id INTEGER NOT NULL,
            online INTEGER NOT NULL,
            registrado_em TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (impressora_id) REFERENCES impressoras(id) ON DELETE CASCADE
        )`);
        db.run('SELECT 1', resolve);
    });
});

// Seed: cria admin inicial se não existir nenhum usuário
dbReady.then(() => {
    db.get('SELECT COUNT(*) AS total FROM usuarios', [], async (err, row) => {
        if (err || row.total > 0) return;
        try {
            const hash = await hashSenha(ADMIN_SENHA);
            db.run(
                `INSERT INTO usuarios (nome, usuario, senha_hash, perfil, permissoes) VALUES (?, ?, ?, 'admin', ?)`,
                ['Administrador', ADMIN_USER, hash, JSON.stringify(PERMISSOES_PADRAO)],
                (e) => { if (!e) console.log(`✅ Usuário admin criado: ${ADMIN_USER}`); }
            );
        } catch (e) { console.error('Erro ao criar admin:', e); }
    });
});

// ── Middleware stack (ordem: helmet → cors → rate limit → body → static) ─────
// useDefaults:false evita que o Helmet readicione upgrade-insecure-requests
// (sistema interno HTTP — sem TLS)
const cspDirectives = helmet.contentSecurityPolicy.getDefaultDirectives();
delete cspDirectives['upgrade-insecure-requests'];

app.use(helmet({
    hsts: false,
    contentSecurityPolicy: {
        useDefaults: false,
        directives: {
            ...cspDirectives,
            'script-src':      ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            'script-src-attr': ["'unsafe-inline'"],
            // Libera o embed em iframe pelo Gestão (gestao-sbr) — Protocolo de
            // Acoplamento. Sem isso o Helmet cai no default `frame-ancestors: 'self'`
            // e o navegador bloqueia o embed.
            'frame-ancestors': ["'self'", "http://gestao.labsobralnet.ind", "https://gestao.laboratoriosobral.com.br"],
        }
    }
}));

app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
    credentials: true
}));

const limiterGlobal = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 600,
    standardHeaders: true,
    legacyHeaders: false
});

const limiterAuth = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true
});

const limiterDescoberta = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false
});

app.use(limiterGlobal);
app.use(express.json({ limit: '100kb' }));

const publicDirs = [
    path.join(__dirname, '..', 'frontend', 'public'),
    path.join(__dirname, 'public'),
];
const publicDir = publicDirs.find(dir => fs.existsSync(dir)) || publicDirs[0];

// ── Regra: produto externo entra por dentro, não por link ────────────────────
// (PROTOCOLO-DE-ACOPLAMENTO.md, sbrgestao). Navegação de topo (fora do iframe
// do Gestão) pra qualquer página estática mostra um aviso em vez do login;
// dentro do iframe o browser manda `Sec-Fetch-Dest: iframe`, não `document`, e
// passa direto. Chamadas de API (fetch/XHR) usam `Sec-Fetch-Dest: empty` — não
// afeta. Requisições sem esse header (curl, healthcheck do Docker) também
// passam — o gate é só pra navegação de browser real.
const GESTAO_URL_TINTA_BRANCA = process.env.GESTAO_URL_TINTA_BRANCA
    || 'https://gestao.laboratoriosobral.com.br/ti/monitor-impressoras';

function paginaAbraNoGestao(urlGestao) {
    return `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Tinta Branca | Acesso</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%}
  body{
    font-family:system-ui,-apple-system,'Segoe UI',sans-serif;
    background-color:#1a0800;color:#f0f0f0;
    display:flex;align-items:center;justify-content:center;
    text-align:center;position:relative;overflow:hidden;
  }
  body::before{
    content:'';position:fixed;inset:0;pointer-events:none;
    background:
      radial-gradient(ellipse 90% 80% at 20% 50%, rgba(180,60,0,0.55) 0%, transparent 55%),
      radial-gradient(ellipse 60% 70% at 65% 30%, rgba(251,102,2,0.22) 0%, transparent 50%),
      radial-gradient(ellipse 70% 60% at 80% 80%, rgba(120,30,0,0.35) 0%, transparent 55%),
      radial-gradient(ellipse 100% 100% at 50% 50%, rgba(10,4,0,0.85) 0%, transparent 100%);
  }
  .card{position:relative;z-index:1;max-width:420px;padding:0 24px}
  h1{font-size:28px;font-weight:800;color:#FB6602;letter-spacing:0.5px;margin-bottom:12px}
  p{color:rgba(255,255,255,0.65);font-size:15px;line-height:1.5;margin-bottom:28px}
  a.btn{
    display:inline-block;padding:14px 32px;border-radius:8px;
    background:linear-gradient(135deg,#FB6602 0%,#d94e00 100%);
    color:#fff;font-weight:700;text-decoration:none;letter-spacing:0.5px;
  }
</style></head>
<body>
  <div class="card">
    <h1>Abra direto no Gestão SBR</h1>
    <p>O Tinta Branca agora faz parte do Gestão SBR — acesse por lá, sem precisar logar de novo aqui.</p>
    <a class="btn" href="${urlGestao}">Abrir no Gestão SBR</a>
  </div>
</body></html>`;
}

app.use((req, res, next) => {
    if (req.method !== 'GET' || req.path.startsWith('/api/')) return next();
    if (req.headers['sec-fetch-dest'] === 'document') {
        res.set('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(paginaAbraNoGestao(GESTAO_URL_TINTA_BRANCA));
    }
    next();
});

app.use(express.static(publicDir));

// ── SNMP ──────────────────────────────────────────────────────────────────────

// Fallback Brother: OID proprietário com formato TLV binário
// Chaves 0x81-0x84 = níveis percentuais dos suprimentos 1-4
function obterNiveisBrother(ip, comunidade) {
    return new Promise((resolve) => {
        const BROTHER_OID  = '1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.8.0';
        const DESC_OIDS = [
            '1.3.6.1.2.1.43.11.1.1.6.1.1',
            '1.3.6.1.2.1.43.11.1.1.6.1.2',
            '1.3.6.1.2.1.43.11.1.1.6.1.3',
            '1.3.6.1.2.1.43.11.1.1.6.1.4',
        ];
        const NOME_MAP = { black: 'Preto', yellow: 'Amarelo', cyan: 'Ciano', magenta: 'Magenta' };
        const session = snmp.createSession(ip, comunidade || 'public', { timeout: 2000, retries: 0 });
        session.get([BROTHER_OID, ...DESC_OIDS], (err, vbs) => {
            session.close();
            if (err || !vbs[0] || snmp.isVarbindError(vbs[0])) { resolve([]); return; }
            const buf = vbs[0].value;
            if (!Buffer.isBuffer(buf)) { resolve([]); return; }
            // Parsear TLV: key(1) + type(1) + len(1) + value(len bytes)
            const percMap = {};
            let pos = 0;
            while (pos + 2 < buf.length) {
                const key = buf[pos];
                if (key === 0xFF) break;
                const len = buf[pos + 2];
                if (pos + 3 + len > buf.length) break;
                if ((key & 0x80) && len === 4) {
                    const val = buf.readInt32BE(pos + 3);
                    if (val >= 0 && val <= 100) percMap[key & 0x7F] = val;
                }
                pos += 3 + len;
            }
            const suprimentos = [];
            for (let i = 1; i <= 4; i++) {
                if (!(i in percMap)) continue;
                const descVb  = vbs[i];
                if (!descVb || snmp.isVarbindError(descVb)) continue;
                const descRaw = (Buffer.isBuffer(descVb.value) ? descVb.value.toString() : String(descVb.value)).toLowerCase();
                const nome = Object.entries(NOME_MAP).find(([k]) => descRaw.includes(k))?.[1];
                if (nome) suprimentos.push({ nome, percentual: percMap[i] });
            }
            resolve(suprimentos);
        });
    });
}

function obterDadosSNMP(ip, comunidade) {
    return new Promise((resolve) => {
        const session = snmp.createSession(ip, comunidade || 'public', { timeout: 1500, retries: 0 });
        const oids = [
            '1.3.6.1.2.1.43.11.1.1.8.1.1', '1.3.6.1.2.1.43.11.1.1.9.1.1',
            '1.3.6.1.2.1.43.11.1.1.8.1.2', '1.3.6.1.2.1.43.11.1.1.9.1.2',
            '1.3.6.1.2.1.43.11.1.1.8.1.3', '1.3.6.1.2.1.43.11.1.1.9.1.3',
            '1.3.6.1.2.1.43.11.1.1.8.1.4', '1.3.6.1.2.1.43.11.1.1.9.1.4'
        ];
        session.get(oids, async (error, varbinds) => {
            session.close();
            if (error) { resolve({ online: false, suprimentos: [] }); return; }
            const cores = ['Preto', 'Ciano', 'Magenta', 'Amarelo'];
            const suprimentos = [];
            for (let i = 0; i < cores.length; i++) {
                const vbMax  = varbinds[i * 2];
                const vbAtual = varbinds[i * 2 + 1];
                if (!vbMax || !vbAtual) continue;
                if (snmp.isVarbindError(vbMax) || snmp.isVarbindError(vbAtual)) continue;
                const max   = vbMax.value;
                const atual = vbAtual.value;
                let perc;
                if (max > 0) {
                    perc = Math.round((atual / max) * 100);
                } else if (max === -2 && typeof atual === 'number' && atual >= 0) {
                    perc = atual > 100 ? Math.round((atual / 255) * 100) : atual;
                } else {
                    continue;
                }
                suprimentos.push({ nome: cores[i], percentual: Math.max(0, Math.min(100, perc)) });
            }
            // Nenhum suprimento legível — tentar OID proprietário Brother
            if (suprimentos.length === 0) {
                const sups = await obterNiveisBrother(ip, comunidade);
                resolve({ online: true, suprimentos: sups });
                return;
            }
            resolve({ online: true, suprimentos });
        });
    });
}

function obterContadorPaginas(ip, comunidade) {
    return new Promise((resolve) => {
        const session = snmp.createSession(ip, comunidade || 'public', { timeout: 2000, retries: 0 });
        session.get(['1.3.6.1.2.1.43.10.2.1.4.1.1'], (err, varbinds) => {
            session.close();
            if (err || !varbinds[0] || snmp.isVarbindError(varbinds[0])) { resolve(null); return; }
            const val = Number(varbinds[0].value);
            resolve(isNaN(val) || val < 0 ? null : val);
        });
    });
}

async function coletarHistorico() {
    db.all('SELECT id, ip, comunidade FROM impressoras', [], async (err, rows) => {
        if (err || !rows.length) return;
        const agora = new Date().toISOString();
        for (const imp of rows) {
            const [snmpData, paginas] = await Promise.all([
                obterDadosSNMP(imp.ip, imp.comunidade),
                obterContadorPaginas(imp.ip, imp.comunidade)
            ]);
            db.run('INSERT INTO historico_status (impressora_id, online, registrado_em) VALUES (?, ?, ?)',
                [imp.id, snmpData.online ? 1 : 0, agora]);
            for (const s of (snmpData.suprimentos || [])) {
                db.run('INSERT INTO historico_tinta (impressora_id, cor, percentual, coletado_em) VALUES (?, ?, ?, ?)',
                    [imp.id, s.nome, s.percentual, agora]);
            }
            if (paginas !== null) {
                db.run('INSERT INTO historico_paginas (impressora_id, paginas_total, coletado_em) VALUES (?, ?, ?)',
                    [imp.id, paginas, agora]);
            }
        }
    });
}

// ── Descoberta de dispositivo via SNMP ────────────────────────────────────────
const FABRICANTES = ['Canon', 'HP', 'Epson', 'Brother', 'Kyocera'];

function descobrirImpressora(ip) {
    return new Promise((resolve) => {
        const session = snmp.createSession(ip, 'public', { timeout: 2000, retries: 0 });
        const oids = [
            '1.3.6.1.2.1.1.1.0',            // sysDescr
            '1.3.6.1.2.1.25.3.2.1.3.1',     // hrDeviceDescr
            '1.3.6.1.2.1.43.11.1.1.8.1.2',  // C max
            '1.3.6.1.2.1.43.11.1.1.9.1.2',  // C cur
            '1.3.6.1.2.1.43.11.1.1.8.1.3',  // M max
            '1.3.6.1.2.1.43.11.1.1.9.1.3',  // M cur
            '1.3.6.1.2.1.43.11.1.1.8.1.4',  // Y max
            '1.3.6.1.2.1.43.11.1.1.9.1.4',  // Y cur
        ];
        session.get(oids, (error, varbinds) => {
            session.close();
            if (error) {
                return resolve({ online: false, fabricante: '', modelo: '', tipo: 'Colorido', material: 'Toner', comunidade: 'public' });
            }
            const toStr = (vb) => {
                if (!vb || snmp.isVarbindError(vb)) return '';
                return Buffer.isBuffer(vb.value) ? vb.value.toString('utf8') : String(vb.value ?? '');
            };
            const sysDescr      = toStr(varbinds[0]);
            const hrDeviceDescr = toStr(varbinds[1]);
            const texto         = (sysDescr + ' ' + hrDeviceDescr).toLowerCase();

            const fabricante = FABRICANTES.find(f => texto.includes(f.toLowerCase())) || '';
            const modelo     = hrDeviceDescr.trim() || sysDescr.trim();
            const cMax = Number(varbinds[2]?.value) || 0;
            const mMax = Number(varbinds[4]?.value) || 0;
            const yMax = Number(varbinds[6]?.value) || 0;
            const tipo     = (cMax > 0 || mMax > 0 || yMax > 0) ? 'Colorido' : 'Mono';
            const material = /laser|toner/i.test(sysDescr + hrDeviceDescr) ? 'Toner' : 'Tinta';

            resolve({ online: true, fabricante, modelo, tipo, material, comunidade: 'public' });
        });
    });
}

// ── Rotas ─────────────────────────────────────────────────────────────────────

app.get('/api/dashboard', exigirAlgumaPermissao(['dashboard', 'estoque']), (req, res, next) => {
    db.all('SELECT id, nome, ip, modelo, localizacao, comunidade, tipo, material FROM impressoras', [], async (err, rows) => {
        if (err) { console.error(err); return next(err); }

        const cacheValido = dashCache && Date.now() - dashCacheAt < DASH_TTL;

        if (cacheValido) {
            res.json(dashCache);
            if (Date.now() - dashCacheAt > DASH_TTL / 2) refreshDashCache(rows);
            return;
        }

        if (dashCache) {
            res.json(dashCache);
            refreshDashCache(rows);
            return;
        }

        try {
            await refreshDashCache(rows);
            res.json(dashCache || []);
        } catch (e) {
            console.error(e);
            next(e);
        }
    });
});

app.get('/api/impressoras', exigirAlgumaPermissao(['impressoras', 'estoque', 'relatorios']), (req, res, next) => {
    db.all('SELECT id, nome AS fabricante, ip, modelo, localizacao, comunidade, tipo, material FROM impressoras ORDER BY id ASC', [], (err, rows) => {
        if (err) return next(err);
        res.json(rows);
    });
});

app.post('/api/impressoras', exigirPermissao('impressoras'), (req, res, next) => {
    const erros = validarImpressora(req.body, true);
    if (erros.length) return res.status(400).json({ erro: erros.join('; ') });

    const { nome, ip, modelo, localizacao, comunidade, tipo, material } = req.body;
    db.run(
        `INSERT INTO impressoras (nome, ip, modelo, localizacao, comunidade, tipo, material) VALUES (?,?,?,?,?,?,?)`,
        [nome.trim(), ip.trim(), modelo.trim(), localizacao, comunidade || 'public', tipo || 'Colorido', material || 'Toner'],
        (err) => {
            if (err) { console.error(err); return next(err); }
            invalidarCacheDash();
            res.status(201).json({ sucesso: true });
        }
    );
});

app.put('/api/impressoras/:id', exigirPermissao('impressoras'), (req, res, next) => {
    const erros = validarImpressora(req.body, false);
    if (erros.length) return res.status(400).json({ erro: erros.join('; ') });

    const { nome, modelo, ip, localizacao, comunidade, tipo, material } = req.body;
    db.get('SELECT * FROM impressoras WHERE id = ?', [req.params.id], (err, existing) => {
        if (err) { console.error(err); return next(err); }
        if (!existing) return res.status(404).json({ erro: 'Impressora não encontrada' });
        db.run(
            `UPDATE impressoras SET nome = ?, modelo = ?, ip = ?, localizacao = ?, comunidade = ?, tipo = ?, material = ? WHERE id = ?`,
            [
                (nome        ?? existing.nome)?.trim?.()    ?? existing.nome,
                (modelo      ?? existing.modelo)?.trim?.()  ?? existing.modelo,
                (ip          ?? existing.ip)?.trim?.()      ?? existing.ip,
                localizacao  ?? existing.localizacao,
                comunidade   ?? existing.comunidade,
                tipo         ?? existing.tipo,
                material     ?? existing.material,
                req.params.id
            ],
            function (err) {
                if (err) { console.error(err); return next(err); }
                invalidarCacheDash();
                res.json({ sucesso: true });
            }
        );
    });
});

app.delete('/api/impressoras/:id', exigirPermissao('impressoras'), (req, res, next) => {
    db.run('DELETE FROM impressoras WHERE id = ?', req.params.id, function (err) {
        if (err) { console.error(err); return next(err); }
        if (this.changes === 0) return res.status(404).json({ erro: 'Impressora não encontrada' });
        invalidarCacheDash();
        res.status(204).end();
    });
});

app.get('/api/estoque', exigirPermissao('estoque'), (req, res) => {
    db.all('SELECT id, modelo, insumo, quantidade, estado FROM estoque ORDER BY modelo ASC, estado ASC', [], (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/estoque', exigirPermissao('estoque'), (req, res, next) => {
    const erros = validarEstoque(req.body);
    if (erros.length) return res.status(400).json({ erro: erros.join('; ') });

    const { modelo, insumo, quantidade, estado } = req.body;
    db.run(
        `INSERT INTO estoque (modelo, insumo, quantidade, estado) VALUES (?,?,?,?)
         ON CONFLICT(modelo, insumo, estado) DO UPDATE SET quantidade = excluded.quantidade`,
        [modelo, insumo, quantidade, estado || 'Novo'],
        (err) => {
            if (err) { console.error(err); return next(err); }
            res.status(201).json({ sucesso: true });
        }
    );
});

app.delete('/api/estoque/:id', exigirPermissao('estoque'), (req, res, next) => {
    db.run('DELETE FROM estoque WHERE id = ?', req.params.id, function (err) {
        if (err) { console.error(err); return next(err); }
        if (this.changes === 0) return res.status(404).json({ erro: 'Item não encontrado' });
        res.status(204).end();
    });
});

// ── SSO do Protocolo de Acoplamento (público — é a porta de entrada do Gestão) ─
app.get('/api/auth/sso', limiterAuth, async (req, res) => {
    if (!DOCKING_SECRET_ACOPLAMENTO) return res.status(503).send('Acoplamento não configurado.');

    const { token } = req.query;
    if (!token) return res.status(400).send('Token ausente.');

    const payload = verificarTokenAcoplamento(token, DOCKING_SECRET_ACOPLAMENTO);
    if (!payload) return res.status(401).send('Token inválido, expirado ou produto incorreto.');

    try {
        const user = await provisionarUsuarioAcoplado(payload.sub, payload.email);
        if (!user.ativo) return res.status(401).send('Usuário desativado.');

        db.run('UPDATE usuarios SET ultimo_login = datetime(\'now\') WHERE id = ?', [user.id]);
        const permissoes = user.perfil === 'admin' ? PERMISSOES_PADRAO : normalizarPermissoes(user.permissoes);
        const sessao = JSON.stringify({
            token: gerarTokenAdmin(user),
            usuario: user.usuario,
            perfil: user.perfil || 'admin',
            permissoes
        });

        res.set('Content-Type', 'text/html; charset=utf-8');
        res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Tinta Branca</title></head><body>
<script>
  sessionStorage.setItem('ic_token', ${JSON.stringify(sessao)});
  location.replace('admin.html');
</script>
</body></html>`);
    } catch (e) {
        console.error('Erro no acoplamento SSO:', e);
        res.status(500).send('Erro interno no acoplamento.');
    }
});

// ── Autenticação de admin ─────────────────────────────────────────────────────
app.post('/api/auth/login', limiterAuth, (req, res) => {
    const { usuario, senha } = req.body;
    if (!usuario || !senha) return res.status(400).json({ ok: false, erro: 'Preencha usuário e senha.' });

    db.get('SELECT * FROM usuarios WHERE usuario = ? AND ativo = 1', [usuario.trim()], async (err, user) => {
        if (err || !user) {
            return setTimeout(() => res.status(401).json({ ok: false, erro: 'Usuário ou senha incorretos.' }), 800);
        }
        try {
            const ok = await verificarSenha(senha, user.senha_hash);
            if (!ok) return setTimeout(() => res.status(401).json({ ok: false, erro: 'Usuário ou senha incorretos.' }), 800);
            db.run('UPDATE usuarios SET ultimo_login = datetime(\'now\') WHERE id = ?', [user.id]);
            if (user.trocar_senha) {
                return res.json({ ok: true, trocar_senha: true, temp_token: gerarTempToken(user.id), usuario: user.usuario, nome: user.nome });
            }
            const permissoes = user.perfil === 'admin' ? PERMISSOES_PADRAO : normalizarPermissoes(user.permissoes);
            res.json({
                ok: true,
                token: gerarTokenAdmin(user),
                usuario: user.usuario,
                nome: user.nome,
                perfil: user.perfil || 'admin',
                permissoes
            });
        } catch {
            res.status(500).json({ ok: false, erro: 'Erro interno.' });
        }
    });
});

app.post('/api/auth/trocar-senha', async (req, res) => {
    const { temp_token, nova_senha } = req.body;
    if (!temp_token || !nova_senha) return res.status(400).json({ ok: false, erro: 'Dados incompletos.' });
    if (nova_senha.length < 6) return res.status(400).json({ ok: false, erro: 'Senha deve ter ao menos 6 caracteres.' });

    const entry = tempTrocarSenhaTokens.get(temp_token);
    if (!entry || Date.now() > entry.exp) return res.status(401).json({ ok: false, erro: 'Sessão expirada. Faça login novamente.' });

    try {
        const hash = await hashSenha(nova_senha);
        db.run(
            `UPDATE usuarios SET senha_hash = ?, trocar_senha = 0 WHERE id = ?`,
            [hash, entry.userId],
            function(err) {
                if (err || this.changes === 0) return res.status(500).json({ ok: false, erro: 'Erro ao atualizar senha.' });
                tempTrocarSenhaTokens.delete(temp_token);
                db.get('SELECT id, usuario, nome, perfil, permissoes FROM usuarios WHERE id = ?', [entry.userId], (e, user) => {
                    if (e || !user) return res.status(500).json({ ok: false, erro: 'Erro interno.' });
                    const permissoes = user.perfil === 'admin' ? PERMISSOES_PADRAO : normalizarPermissoes(user.permissoes);
                    res.json({ ok: true, token: gerarTokenAdmin(user), usuario: user.usuario, nome: user.nome, perfil: user.perfil || 'admin', permissoes });
                });
            }
        );
    } catch { res.status(500).json({ ok: false, erro: 'Erro interno.' }); }
});

app.get('/api/auth/verify', (req, res) => {
    const auth  = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const entry = adminTokens.get(token);
    const exp   = typeof entry === 'number' ? entry : entry?.exp;
    if (!exp || Date.now() > exp) return res.status(401).json({ ok: false });
    const user = typeof entry === 'number' ? { perfil:'admin', permissoes:PERMISSOES_PADRAO } : entry;
    res.json({ ok: true, perfil: user.perfil, permissoes: user.permissoes });
});

// ── Gestão de usuários ────────────────────────────────────────────────────────
app.get('/api/usuarios', exigirPermissao('usuarios'), (req, res) => {
    db.all('SELECT id, nome, usuario, trocar_senha, perfil, permissoes, ativo, criado_em, ultimo_login FROM usuarios ORDER BY criado_em', [], (err, rows) => {
        if (err) return res.status(500).json({ erro: 'Erro ao listar usuários.' });
        res.json(rows.map(u => ({ ...u, permissoes: normalizarPermissoes(u.permissoes) })));
    });
});

app.post('/api/usuarios', exigirPermissao('usuarios'), async (req, res) => {
    const { nome, usuario, senha, perfil, permissoes } = req.body;
    if (!nome || !usuario || !senha) return res.status(400).json({ erro: 'Nome, usuário e senha são obrigatórios.' });
    if (senha.length < 6) return res.status(400).json({ erro: 'Senha deve ter ao menos 6 caracteres.' });
    const perfilFinal = perfil === 'operador' ? 'operador' : 'admin';
    const permsFinal = perfilFinal === 'admin' ? PERMISSOES_PADRAO : normalizarPermissoes(permissoes);
    try {
        const hash = await hashSenha(senha);
        db.run(
            `INSERT INTO usuarios (nome, usuario, senha_hash, trocar_senha, perfil, permissoes) VALUES (?, ?, ?, 1, ?, ?)`,
            [nome.trim(), usuario.trim().toLowerCase(), hash, perfilFinal, JSON.stringify(permsFinal)],
            function(err) {
                if (err) return res.status(409).json({ erro: 'Usuário já existe.' });
                res.status(201).json({ ok: true, id: this.lastID });
            }
        );
    } catch { res.status(500).json({ erro: 'Erro interno.' }); }
});

app.put('/api/usuarios/:id', exigirPermissao('usuarios'), async (req, res) => {
    const { nome, senha, ativo, trocar_senha, perfil, permissoes } = req.body;
    const fields = [];
    const vals   = [];
    if (nome  !== undefined) { fields.push('nome = ?');  vals.push(nome.trim()); }
    if (ativo !== undefined) { fields.push('ativo = ?'); vals.push(ativo ? 1 : 0); }
    if (perfil !== undefined) {
        const perfilFinal = perfil === 'operador' ? 'operador' : 'admin';
        fields.push('perfil = ?'); vals.push(perfilFinal);
        fields.push('permissoes = ?'); vals.push(JSON.stringify(perfilFinal === 'admin' ? PERMISSOES_PADRAO : normalizarPermissoes(permissoes)));
    } else if (permissoes !== undefined) {
        fields.push('permissoes = ?'); vals.push(JSON.stringify(normalizarPermissoes(permissoes)));
    }
    if (senha) {
        if (senha.length < 6) return res.status(400).json({ erro: 'Senha deve ter ao menos 6 caracteres.' });
        try { fields.push('senha_hash = ?'); vals.push(await hashSenha(senha)); } catch { return res.status(500).json({ erro: 'Erro interno.' }); }
        fields.push('trocar_senha = ?'); vals.push(trocar_senha === false ? 0 : 1);
    } else if (trocar_senha !== undefined) {
        fields.push('trocar_senha = ?'); vals.push(trocar_senha ? 1 : 0);
    }
    if (!fields.length) return res.status(400).json({ erro: 'Nenhum campo para atualizar.' });
    vals.push(req.params.id);
    db.run(`UPDATE usuarios SET ${fields.join(', ')} WHERE id = ?`, vals, function(err) {
        if (err) return res.status(500).json({ erro: 'Erro ao atualizar.' });
        if (this.changes === 0) return res.status(404).json({ erro: 'Usuário não encontrado.' });
        res.json({ ok: true });
    });
});

app.delete('/api/usuarios/:id', exigirPermissao('usuarios'), (req, res) => {
    db.get('SELECT COUNT(*) AS total FROM usuarios WHERE ativo = 1', [], (err, row) => {
        if (err) return res.status(500).json({ erro: 'Erro interno.' });
        if (row.total <= 1) return res.status(400).json({ erro: 'Não é possível remover o único usuário ativo.' });
        db.run('DELETE FROM usuarios WHERE id = ?', [req.params.id], function(err) {
            if (err) return res.status(500).json({ erro: 'Erro ao remover.' });
            if (this.changes === 0) return res.status(404).json({ erro: 'Usuário não encontrado.' });
            res.status(204).end();
        });
    });
});

// ── Autenticação de estoque ───────────────────────────────────────────────────
app.post('/api/auth/estoque', limiterAuth, (req, res) => {
    const { senha } = req.body;
    if (!senha) return res.status(400).json({ ok: false });
    if (senha === ESTOQUE_SENHA) return res.json({ ok: true, token: gerarTokenEstoque() });
    setTimeout(() => res.status(401).json({ ok: false }), 800);
});

// ── Gerador de PDF mínimo para impressão ─────────────────────────────────────
function gerarPDF(texto, relatorio = null) {
    const esc = s => String(s ?? '')
        .normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
        .replace(/[^\x20-\x7E]/g, ' ')
        .replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
    const num = n => Number(n || 0).toFixed(2).replace(/\.00$/, '');
    const rgb = {
        accent: [0.98, 0.40, 0.01], ink: [0.08, 0.10, 0.14], muted: [0.38, 0.41, 0.46],
        line: [0.86, 0.87, 0.89], ok: [0.06, 0.55, 0.34], warn: [0.88, 0.45, 0.03],
        bad: [0.75, 0.12, 0.12], cyan: [0.02, 0.62, 0.72], magenta: [0.75, 0.12, 0.55],
        yellow: [0.90, 0.66, 0.04], black: [0.08, 0.10, 0.14], def: [0.98, 0.40, 0.01],
        white: [1, 1, 1]
    };
    const c = arr => `${num(arr[0])} ${num(arr[1])} ${num(arr[2])}`;
    const corTinta = nome => {
        const n = String(nome || '').toLowerCase();
        if (n.includes('cyan') || n.includes('ciano')) return rgb.cyan;
        if (n.includes('magenta')) return rgb.magenta;
        if (n.includes('yellow') || n.includes('amarelo')) return rgb.yellow;
        if (n.includes('black') || n.includes('preto')) return rgb.black;
        return rgb.def;
    };
    const pages = [];
    let ops = [];
    let y = 800;
    const margin = 42, width = 595, height = 842, usable = width - margin * 2;
    const newPage = () => { if (ops.length) pages.push(ops.join('\n')); ops = []; y = 800; };
    const ensure = h => { if (y - h < 44) newPage(); };
    const rect = (x, ry, w, h, color) => ops.push(`q ${c(color)} rg ${num(x)} ${num(ry)} ${num(w)} ${num(h)} re f Q`);
    const textAt = (s, x, ty, size = 10, color = rgb.ink, font = 'F1') =>
        ops.push(`BT /${font} ${size} Tf ${c(color)} rg ${num(x)} ${num(ty)} Td (${esc(s)}) Tj ET`);
    const wrap = (s, max = 88) => {
        const words = esc(s).split(/\s+/).filter(Boolean);
        const lines = [];
        let cur = '';
        words.forEach(w => {
            if ((cur + ' ' + w).trim().length > max) { if (cur) lines.push(cur); cur = w; }
            else cur = (cur + ' ' + w).trim();
        });
        if (cur) lines.push(cur);
        return lines.length ? lines : [''];
    };
    const section = title => {
        ensure(38);
        y -= 16;
        rect(margin, y - 5, 5, 20, rgb.accent);
        textAt(title, margin + 12, y, 13, rgb.ink, 'F2');
        y -= 18;
        rect(margin, y, usable, 0.8, rgb.line);
        y -= 10;
    };
    const bodyLines = raw => {
        String(raw || '').split('\n').forEach(line => {
            const clean = line.replace(/\s*\|\s*/g, '   ');
            if (!clean.trim()) { y -= 6; return; }
            wrap(clean, 96).forEach(l => {
                ensure(14);
                textAt(l, margin, y, 9, rgb.ink);
                y -= 13;
            });
        });
    };
    const tintaBars = rows => {
        const latest = {};
        (Array.isArray(rows) ? rows : []).forEach(r => {
            const cor = r.cor || r.nome || 'Tinta';
            if (!latest[cor] || String(r.dia || '') >= String(latest[cor].dia || '')) latest[cor] = r;
        });
        Object.values(latest).forEach(r => {
            const pct = Math.max(0, Math.min(100, Number(r.percentual_medio ?? r.percentual ?? 0)));
            ensure(36);
            textAt(`${r.cor || r.nome || 'Tinta'} - ${pct}%`, margin, y, 10, pct <= 10 ? rgb.bad : pct <= 25 ? rgb.warn : rgb.ink, 'F2');
            y -= 14;
            rect(margin, y, usable, 10, rgb.line);
            rect(margin, y, usable * pct / 100, 10, corTinta(r.cor || r.nome));
            y -= 20;
        });
    };

    rect(0, 786, width, 56, rgb.accent);
    textAt(relatorio?.titulo || 'Relatorio de impressoras', margin, 812, 18, rgb.white, 'F2');
    textAt(`Gerado em ${new Date().toLocaleString('pt-BR')}`, margin, 794, 9, rgb.white);
    y = 760;
    if (relatorio && Array.isArray(relatorio.secoes)) {
        relatorio.secoes.forEach(secao => {
            section(secao.titulo || 'Secao');
            if (Array.isArray(secao.tinta) && secao.tinta.length) tintaBars(secao.tinta);
            bodyLines(secao.texto || '');
        });
    } else {
        section('Conteudo');
        bodyLines(texto);
    }
    newPage();

    const objects = ['1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'];
    const kids = pages.map((_, i) => `${3 + i * 2} 0 R`).join(' ');
    objects.push(`2 0 obj\n<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>\nendobj\n`);
    pages.forEach((stream, i) => {
        const pageObj = 3 + i * 2, contentObj = pageObj + 1;
        objects.push(`${pageObj} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${width} ${height}] /Contents ${contentObj} 0 R /Resources << /Font << /F1 ${3 + pages.length * 2} 0 R /F2 ${4 + pages.length * 2} 0 R >> >> >>\nendobj\n`);
        objects.push(`${contentObj} 0 obj\n<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}\nendstream\nendobj\n`);
    });
    const font1 = 3 + pages.length * 2, font2 = font1 + 1;
    objects.push(`${font1} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`);
    objects.push(`${font2} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n`);
    const hdr = '%PDF-1.4\n';
    const offsets = [];
    let pos = Buffer.byteLength(hdr, 'latin1');
    objects.forEach(o => { offsets.push(pos); pos += Buffer.byteLength(o, 'latin1'); });
    const xrefPos = pos;
    const p = n => String(n).padStart(10, '0');
    const xref = 'xref\n0 ' + (objects.length + 1) + '\n0000000000 65535 f \r\n' +
        offsets.map(o => `${p(o)} 00000 n \r\n`).join('');
    const trailer = `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`;
    return Buffer.concat([hdr, ...objects, xref, trailer].map(s => Buffer.from(s, 'latin1')));
}

// ── Impressão via IPP + PDF (Canon MF / AirPrint) ────────────────────────────
app.post('/api/impressoras/:id/imprimir', exigirPermissao('imprimir'), (req, res, next) => {
    const { conteudo, relatorio } = req.body;
    if (!conteudo) return res.status(400).json({ erro: 'Conteúdo não informado' });

    db.get('SELECT * FROM impressoras WHERE id = ?', [req.params.id], (err, imp) => {
        if (err || !imp) return res.status(404).json({ erro: 'Impressora não encontrada' });

        const docBuf = gerarPDF(conteudo, relatorio);

        function ippAttr(tag, name, value) {
            const nb = Buffer.from(name, 'utf8'), vb = Buffer.from(value, 'utf8');
            const b  = Buffer.alloc(5 + nb.length + vb.length);
            b.writeUInt8(tag, 0); b.writeUInt16BE(nb.length, 1); nb.copy(b, 3);
            b.writeUInt16BE(vb.length, 3 + nb.length); vb.copy(b, 5 + nb.length);
            return b;
        }

        const printerUri = `ipp://${imp.ip}/ipp/print`;

        function enviarIPP(docFormat, docBuffer, onSuccess, onFail) {
            const a = Buffer.concat([
                Buffer.from([0x01]),
                ippAttr(0x47, 'attributes-charset',         'utf-8'),
                ippAttr(0x48, 'attributes-natural-language', 'pt-br'),
                ippAttr(0x45, 'printer-uri',                 printerUri),
                ippAttr(0x42, 'requesting-user-name',        'Sistema'),
                ippAttr(0x42, 'job-name',                    'Impressao'),
                ippAttr(0x44, 'document-format',             docFormat),
                Buffer.from([0x03])
            ]);
            const h = Buffer.alloc(8);
            h.writeUInt8(0x01,0); h.writeUInt8(0x01,1);
            h.writeUInt16BE(0x0002,2); h.writeInt32BE(1,4);
            const body = Buffer.concat([h, a, docBuffer]);

            const r = http.request({
                hostname: imp.ip, port: 631, path: '/ipp/print', method: 'POST',
                headers: { 'Content-Type': 'application/ipp', 'Content-Length': body.length }
            }, ippRes => {
                const chunks = [];
                ippRes.on('data', c => chunks.push(c));
                ippRes.on('end', () => {
                    const buf = Buffer.concat(chunks);
                    const sc  = buf.length >= 4 ? buf.readUInt16BE(2) : 0;
                    if (sc >= 0x0400) return onFail(sc);
                    onSuccess();
                });
            });
            r.on('error', () => onFail(null));
            r.setTimeout(10000, () => r.destroy());
            r.write(body); r.end();
        }

        function enviarRaw(onSuccess, onFail) {
            const socket = new net.Socket();
            const buf = Buffer.from(conteudo.split('\n').join('\r\n') + '\r\n\f', 'utf8');
            socket.setTimeout(5000);
            socket.connect(9100, imp.ip, () => {
                socket.write(buf, () => { socket.end(); onSuccess('RAW'); });
            });
            socket.on('timeout', () => { socket.destroy(); onFail('Timeout na porta 9100'); });
            socket.on('error',   () => onFail('Impressora não respondeu em IPP nem RAW'));
        }

        // Cascata: PDF → octet-stream → RAW
        const textBuf = Buffer.from(conteudo + '\n', 'utf8');
        enviarIPP('application/pdf', docBuf,
            () => res.json({ sucesso: true }),
            sc1 => enviarIPP('application/octet-stream', textBuf,
                () => res.json({ sucesso: true }),
                sc2 => enviarRaw(
                    via  => res.json({ sucesso: true, aviso: `Enviado via ${via}` }),
                    msg  => res.status(500).json({ erro: msg || `IPP ${sc1 ? sc1.toString(16) : sc2 ? sc2.toString(16) : '?'}` })
                )
            )
        );
    });
});

app.get('/api/descobrir', limiterDescoberta, async (req, res, next) => {
    const ip = String(req.query.ip || '').trim();
    if (!IPV4_RE.test(ip)) return res.status(400).json({ erro: 'IP inválido' });
    try {
        res.json(await descobrirImpressora(ip));
    } catch (e) {
        next(e);
    }
});

// ── Error handler centralizado (deve ser o último middleware) ─────────────────
// ── Relatórios ────────────────────────────────────────────────────────────────

app.get('/api/relatorios/impressoras', exigirPermissao('relatorios'), (req, res, next) => {
    db.all('SELECT id, nome, ip, modelo, localizacao, tipo, material, comunidade FROM impressoras ORDER BY nome ASC', [], async (err, rows) => {
        if (err) return next(err);
        const resultados = await Promise.all(rows.map(async (imp) => {
            const [snmpData, paginas] = await Promise.all([
                obterDadosSNMP(imp.ip, imp.comunidade || 'public'),
                obterContadorPaginas(imp.ip, imp.comunidade || 'public')
            ]);
            return { ...imp, ...snmpData, paginas_total: paginas };
        }));
        res.json(resultados);
    });
});

app.get('/api/relatorios/paginas/:id', exigirPermissao('relatorios'), (req, res, next) => {
    const fmtMap = { hora: '%Y-%m-%dT%H:00', dia: '%Y-%m-%d', mes: '%Y-%m', ano: '%Y' };
    const janMap = { hora: '-2 days', dia: '-30 days', mes: '-12 months', ano: '-5 years' };
    const fmt = fmtMap[req.query.periodo] || fmtMap.dia;
    const jan = janMap[req.query.periodo] || janMap.dia;
    db.all(
        `SELECT strftime('${fmt}', coletado_em) AS periodo,
                MAX(paginas_total) - MIN(paginas_total) AS paginas_impressas
         FROM historico_paginas
         WHERE impressora_id = ? AND coletado_em >= datetime('now', '${jan}')
         GROUP BY strftime('${fmt}', coletado_em)
         ORDER BY periodo ASC`,
        [req.params.id], (err, rows) => {
            if (err) return next(err);
            const periodos = rows.filter(r => (r.paginas_impressas || 0) > 0);
            db.get('SELECT MAX(paginas_total) AS total FROM historico_paginas WHERE impressora_id = ?',
                [req.params.id], (err2, meta) => {
                    res.json({ periodos, total_atual: meta ? meta.total : null });
                });
        }
    );
});

app.get('/api/relatorios/tinta/:id', exigirPermissao('relatorios'), (req, res, next) => {
    db.all(
        `SELECT cor,
                strftime('%Y-%m-%d', coletado_em) AS dia,
                ROUND(AVG(percentual)) AS percentual_medio,
                MIN(percentual) AS percentual_min
         FROM historico_tinta
         WHERE impressora_id = ? AND coletado_em >= datetime('now', '-30 days')
         GROUP BY cor, strftime('%Y-%m-%d', coletado_em)
         ORDER BY dia ASC, cor ASC`,
        [req.params.id], (err, rows) => {
            if (err) return next(err);
            res.json(rows);
        }
    );
});

app.get('/api/relatorios/trocas-toner', exigirPermissao('relatorios'), (req, res, next) => {
    const diasPermitidos = new Set([7, 30, 90, 180]);
    const dias = diasPermitidos.has(Number(req.query.dias)) ? Number(req.query.dias) : 30;
    db.all(
        `SELECT h.impressora_id,
                i.nome, i.ip, i.modelo, i.localizacao,
                h.cor, h.percentual, h.coletado_em
         FROM historico_tinta h
         JOIN impressoras i ON i.id = h.impressora_id
         WHERE h.coletado_em >= datetime('now', ?)
         ORDER BY h.impressora_id ASC, h.cor ASC, h.coletado_em ASC`,
        [`-${dias} days`], (err, rows) => {
            if (err) return next(err);
            const grupos = new Map();
            for (const row of rows) {
                const key = `${row.impressora_id}:${String(row.cor || '').toLowerCase()}`;
                if (!grupos.has(key)) grupos.set(key, []);
                grupos.get(key).push(row);
            }
            const eventos = [];
            for (const pontos of grupos.values()) {
                for (let i = 1; i < pontos.length; i++) {
                    const anterior = Number(pontos[i - 1].percentual || 0);
                    const atual = Number(pontos[i].percentual || 0);
                    const diferenca = atual - anterior;
                    if (diferenca >= 35 && atual >= 60) {
                        const p = pontos[i];
                        eventos.push({
                            id: `auto-${p.impressora_id}-${p.cor}-${p.coletado_em}`,
                            origem: 'automatica',
                            impressora_id: p.impressora_id,
                            nome: p.nome,
                            ip: p.ip,
                            modelo: p.modelo,
                            localizacao: p.localizacao,
                            cor: p.cor,
                            data: p.coletado_em,
                            percentual_anterior: anterior,
                            percentual_atual: atual,
                            diferenca
                        });
                    }
                }
            }
            db.all(
                `SELECT t.id, t.impressora_id, i.nome, i.ip, i.modelo, i.localizacao,
                        t.cor, t.percentual_anterior, t.percentual_novo AS percentual_atual,
                        (COALESCE(t.percentual_novo, 0) - COALESCE(t.percentual_anterior, 0)) AS diferenca,
                        t.observacao, t.usuario, t.registrado_em AS data
                 FROM trocas_toner t
                 JOIN impressoras i ON i.id = t.impressora_id
                 WHERE t.registrado_em >= datetime('now', ?)
                 ORDER BY t.registrado_em DESC`,
                [`-${dias} days`], (err2, manuais) => {
                    if (err2) return next(err2);
                    for (const m of manuais) eventos.push({ ...m, origem: 'manual' });
                    eventos.sort((a, b) => String(b.data).localeCompare(String(a.data)));
                    const totalManual = eventos.filter(e => e.origem === 'manual').length;
                    const totalAutomatico = eventos.filter(e => e.origem === 'automatica').length;
                    res.json({
                        periodo_dias: dias,
                        total: eventos.length,
                        total_manual: totalManual,
                        total_automatico: totalAutomatico,
                        eventos
                    });
                }
            );
        }
    );
});

app.post('/api/relatorios/trocas-toner', exigirPermissao('relatorios'), (req, res, next) => {
    const { impressora_id, cor, percentual_anterior, percentual_novo, observacao } = req.body;
    const impId = Number(impressora_id);
    const corLimpa = String(cor || '').trim();
    if (!Number.isInteger(impId) || impId <= 0) return res.status(400).json({ erro: 'Impressora inválida' });
    if (!corLimpa) return res.status(400).json({ erro: 'Informe a cor do toner' });
    const pctAnt = percentual_anterior === '' || percentual_anterior == null ? null : Number(percentual_anterior);
    const pctNovo = percentual_novo === '' || percentual_novo == null ? null : Number(percentual_novo);
    if (pctAnt != null && (pctAnt < 0 || pctAnt > 100)) return res.status(400).json({ erro: 'Percentual anterior inválido' });
    if (pctNovo != null && (pctNovo < 0 || pctNovo > 100)) return res.status(400).json({ erro: 'Percentual novo inválido' });
    db.get('SELECT id FROM impressoras WHERE id = ?', [impId], (err, imp) => {
        if (err) return next(err);
        if (!imp) return res.status(404).json({ erro: 'Impressora não encontrada' });
        const usuario = req.body.usuario || 'Administrador';
        db.run(
            `INSERT INTO trocas_toner
             (impressora_id, cor, percentual_anterior, percentual_novo, observacao, usuario)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [impId, corLimpa, pctAnt, pctNovo, String(observacao || '').trim(), usuario],
            function(insertErr) {
                if (insertErr) return next(insertErr);
                res.status(201).json({ sucesso: true, id: this.lastID });
            }
        );
    });
});

app.get('/api/relatorios/disponibilidade', exigirPermissao('relatorios'), (req, res, next) => {
    db.all(
        `SELECT i.id, i.nome, i.ip, i.modelo, i.localizacao,
                COUNT(h.id) AS total_checkins,
                SUM(COALESCE(h.online, 0)) AS checkins_online,
                ROUND(100.0 * SUM(COALESCE(h.online, 0)) / MAX(COUNT(h.id), 1), 1) AS uptime_pct,
                MAX(CASE WHEN h.online = 0 THEN h.registrado_em END) AS ultimo_offline
         FROM impressoras i
         LEFT JOIN historico_status h
                ON h.impressora_id = i.id AND h.registrado_em >= datetime('now', '-30 days')
         GROUP BY i.id ORDER BY uptime_pct ASC, i.nome ASC`,
        [], (err, rows) => {
            if (err) return next(err);
            res.json(rows);
        }
    );
});

app.get('/api/relatorios/estoque', exigirPermissao('relatorios'), (req, res, next) => {
    db.all(
        `SELECT e.modelo, e.insumo, e.quantidade AS estoque_atual,
                ROUND(AVG(c.consumo_dia), 3) AS consumo_dia_medio,
                CASE WHEN ROUND(AVG(c.consumo_dia), 3) > 0
                     THEN ROUND(e.quantidade / ROUND(AVG(c.consumo_dia), 3))
                     ELSE NULL END AS dias_estimados
         FROM estoque e
         LEFT JOIN (
             SELECT impressora_id, cor,
                    (MAX(percentual) - MIN(percentual)) /
                    MAX(julianday(MAX(coletado_em)) - julianday(MIN(coletado_em)), 1) AS consumo_dia
             FROM historico_tinta
             WHERE coletado_em >= datetime('now', '-30 days')
             GROUP BY impressora_id, cor
         ) c ON LOWER(c.cor) = LOWER(
             CASE WHEN LOWER(e.insumo) LIKE '%preto%'   OR LOWER(e.insumo) LIKE '%black%'   THEN 'preto'
                  WHEN LOWER(e.insumo) LIKE '%ciano%'   OR LOWER(e.insumo) LIKE '%cyan%'    THEN 'ciano'
                  WHEN LOWER(e.insumo) LIKE '%magenta%'                                      THEN 'magenta'
                  WHEN LOWER(e.insumo) LIKE '%amarelo%' OR LOWER(e.insumo) LIKE '%yellow%'  THEN 'amarelo'
                  ELSE e.insumo END)
         GROUP BY e.id ORDER BY dias_estimados ASC, e.modelo ASC`,
        [], (err, rows) => {
            if (err) return next(err);
            res.json(rows);
        }
    );
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error(`[${new Date().toISOString()}] ${req.method} ${req.url}`, err);
    res.status(500).json({ erro: 'Erro interno do servidor' });
});

module.exports = { app, db, dbReady, estoqueTokens };

// ── Inicialização e graceful shutdown (apenas quando executado diretamente) ────
if (require.main === module) {
    const PORT   = process.env.PORT || 3000;
    const server = app.listen(PORT, () => console.log(`Servidor em http://localhost:${PORT}`));

    dbReady.then(() => {
        coletarHistorico();
        setInterval(coletarHistorico, 60 * 60 * 1000).unref();
    });

    function encerrar(sinal) {
        console.log(`\n${sinal} recebido. Encerrando servidor...`);
        server.close(() => {
            db.close(() => process.exit(0));
        });
        setTimeout(() => process.exit(1), 10000).unref();
    }

    process.on('SIGTERM', () => encerrar('SIGTERM'));
    process.on('SIGINT',  () => encerrar('SIGINT'));

    process.on('unhandledRejection', (reason) => {
        console.error('unhandledRejection:', reason);
        process.exit(1);
    });

    process.on('uncaughtException', (err) => {
        console.error('uncaughtException:', err);
        process.exit(1);
    });
}
