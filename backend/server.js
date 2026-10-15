const express      = require('express');
const sqlite3      = require('sqlite3').verbose();
const snmp         = require('net-snmp');
const net          = require('net');
const http         = require('http');
const https        = require('https');
const helmet       = require('helmet');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const crypto       = require('crypto');
const fs           = require('fs');
const path         = require('path');

const app = express();

// Atrás de 1 proxy reverso (Apache no .214, HTTP e HTTPS) — sem isso o
// express-rate-limit rejeita o X-Forwarded-For que o Apache já envia
// (ERR_ERL_UNEXPECTED_X_FORWARDED_FOR), quebrando as rotas com rate limit
// (ex.: /api/auth/sso).
app.set('trust proxy', 1);

// ── Validação de IP e campos de impressora ────────────────────────────────────
const IPV4_RE = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

// Impressora conectada via USB: sem IP, sem consulta SNMP nem histórico de status
const CONEXOES = ['rede', 'usb'];

function ehUSB(imp) {
    return imp?.conexao === 'usb';
}

function validarImpressora(body, obrigatorio = true) {
    const erros = [];
    const { nome, ip, modelo, conexao } = body;
    if (obrigatorio || nome !== undefined) {
        if (!nome || typeof nome !== 'string' || !nome.trim()) erros.push('nome é obrigatório');
    }
    if (conexao !== undefined && !CONEXOES.includes(conexao)) erros.push("conexao deve ser 'rede' ou 'usb'");
    const ipTexto = String(ip ?? '').trim();
    if (ipTexto && !IPV4_RE.test(ipTexto)) erros.push('ip inválido (use formato IPv4)');
    else if (obrigatorio && !ipTexto && conexao !== 'usb') erros.push('ip é obrigatório para impressora de rede');
    if (obrigatorio || modelo !== undefined) {
        if (!modelo || typeof modelo !== 'string' || !modelo.trim()) erros.push('modelo é obrigatório');
    }
    const { numero_serie } = body;
    if (numero_serie !== undefined && numero_serie !== null && (typeof numero_serie !== 'string' || numero_serie.length > 64)) {
        erros.push('numero_serie deve ser texto de até 64 caracteres');
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
            const snmpData = ehUSB(imp) ? SEM_MONITORAMENTO : await obterDadosSNMP(imp.ip, imp.comunidade);
            return {
                ...imp, material: imp.material || 'Toner', tipo: imp.tipo || 'Colorido', ...snmpData,
                aparelho_divergente: serieDivergente(imp.numero_serie, snmpData.serie_detectada),
                leitura_suspeita: leituraSuspeitaAtual(imp.id, snmpData)
            };
        }));
        dashCache   = resultados;
        dashCacheAt = Date.now();
    } finally {
        dashRefreshing = false;
    }
}

// ── Sessões de admin ──────────────────────────────────────────────────────────
// Não há login por usuário/senha: a única porta de entrada é o SSO do Gestão
// (/api/auth/sso), que emite o token de sessão abaixo.
const ADMIN_USER = 'admin';

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

// Auditoria de impressão por usuário (page_log do CUPS via PRINTSRV/.216).
// Ausente = coleta desativada, nunca falha silenciosamente com erro de rede.
const PAGELOG_API_URL   = process.env.PAGELOG_API_URL;
const PAGELOG_API_TOKEN = process.env.PAGELOG_API_TOKEN;

const dbReady = new Promise(resolve => {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS impressoras (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT, ip TEXT, modelo TEXT, localizacao TEXT, comunidade TEXT, tipo TEXT, material TEXT
        )`);
        db.run(`ALTER TABLE impressoras ADD COLUMN material TEXT`, () => {});
        db.run(`ALTER TABLE impressoras ADD COLUMN tipo TEXT`, () => {});
        db.run(`ALTER TABLE impressoras ADD COLUMN numero_serie TEXT`, () => {});
        db.run(`ALTER TABLE impressoras ADD COLUMN conexao TEXT NOT NULL DEFAULT 'rede'`, () => {});
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
        // Histórico cresce ~1 linha por impressora/cor por hora — consultas por impressora e data
        db.run(`CREATE INDEX IF NOT EXISTS idx_historico_tinta_impressora ON historico_tinta (impressora_id, coletado_em)`);
        db.run(`CREATE INDEX IF NOT EXISTS idx_historico_paginas_impressora ON historico_paginas (impressora_id, coletado_em)`);
        db.run(`CREATE INDEX IF NOT EXISTS idx_historico_status_impressora ON historico_status (impressora_id, registrado_em)`);
        db.run(`CREATE TABLE IF NOT EXISTS impressoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            impressora TEXT,
            usuario TEXT,
            job_id INTEGER,
            paginas INTEGER,
            copias INTEGER,
            hostname_origem TEXT,
            documento TEXT,
            registrado_em TEXT DEFAULT (datetime('now'))
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS impressoes_cursor (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_line INTEGER NOT NULL DEFAULT 0,
            last_line_jobpages INTEGER NOT NULL DEFAULT 0
        )`);
        db.run(`ALTER TABLE impressoes_cursor ADD COLUMN last_line_jobpages INTEGER NOT NULL DEFAULT 0`, () => {});
        db.run(`INSERT OR IGNORE INTO impressoes_cursor (id, last_line, last_line_jobpages) VALUES (1, 0, 0)`);
        db.run('SELECT 1', resolve);
    });
});

// ── Middleware stack (ordem: helmet → cors → rate limit → body → static) ─────
// useDefaults:false evita que o Helmet readicione upgrade-insecure-requests
// (sistema interno HTTP — sem TLS)
const cspDirectives = helmet.contentSecurityPolicy.getDefaultDirectives();
delete cspDirectives['upgrade-insecure-requests'];

app.use(helmet({
    hsts: false,
    // X-Frame-Options é um header legado que só suporta DENY/SAMEORIGIN — não
    // entende múltiplas origens. Com o Gestão embutindo este produto de uma
    // origem DIFERENTE (gestao.laboratoriosobral.com.br), SAMEORIGIN bloqueia
    // o embed mesmo com o CSP frame-ancestors abaixo liberando explicitamente.
    // Desliga o header legado e confia só no CSP moderno (todo browser atual
    // já prioriza frame-ancestors sobre X-Frame-Options quando os dois existem,
    // mas alguns ainda aplicam o mais restritivo — mais seguro remover o legado).
    frameguard: false,
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
// do Gestão) pra qualquer página estática redireciona direto pro Gestão, sem
// página intermediária — nenhum link "avulso" deve parecer um destino válido
// por si só. Dentro do iframe o browser manda `Sec-Fetch-Dest: iframe`, não
// `document`, e passa direto. Chamadas de API (fetch/XHR) usam
// `Sec-Fetch-Dest: empty` — não afeta. Requisições sem esse header (curl,
// healthcheck do Docker) também passam — o gate é só pra navegação de browser real.
const GESTAO_URL_TINTA_BRANCA = process.env.GESTAO_URL_TINTA_BRANCA
    || 'https://gestao.laboratoriosobral.com.br/ti/monitor-impressoras';

app.use((req, res, next) => {
    if (req.method !== 'GET' || req.path.startsWith('/api/')) return next();
    if (req.headers['sec-fetch-dest'] === 'document') {
        return res.redirect(302, GESTAO_URL_TINTA_BRANCA);
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

// ── Consulta SNMP de impressora (Printer-MIB, RFC 3805) ───────────────────────
// Lê identificação (descrição, modelo, nº de série) e a tabela prtMarkerSupplies
// item a item (tipo, cor, máximo, nível), usando o tipo/cor que a própria
// impressora informa em vez de supor pela posição. Uma requisição por item: no
// SNMP v1 um único OID inexistente faz a requisição inteira falhar
// (noSuchName) — pedir as 4 cores de uma vez fazia impressoras monocromáticas
// aparecerem sempre offline.
const OID_SYS_DESCR        = '1.3.6.1.2.1.1.1.0';
const OID_MODELO           = '1.3.6.1.2.1.25.3.2.1.3.1';    // hrDeviceDescr
const OID_NUMERO_SERIE     = '1.3.6.1.2.1.43.5.1.1.17.1';   // prtGeneralSerialNumber
const OID_SUPRIMENTOS      = '1.3.6.1.2.1.43.11.1.1';       // prtMarkerSuppliesEntry
const OID_CORANTES         = '1.3.6.1.2.1.43.12.1.1.4.1';   // prtMarkerColorantValue
const TIPOS_TINTA          = new Set([5, 6]);               // ink, inkCartridge
const TIPOS_TONER          = new Set([3, 21]);              // toner, tonerCartridge
const NOMES_COR            = [['black', 'Preto'], ['cyan', 'Ciano'], ['magenta', 'Magenta'], ['yellow', 'Amarelo']];
const ORDEM_CORES          = NOMES_COR.map(([, nome]) => nome);
const MAX_ITENS_SUPRIMENTO = 12;

function textoSNMP(valor) {
    return Buffer.isBuffer(valor) ? valor.toString().replace(/\0/g, '').trim() : String(valor ?? '').trim();
}

function ehTintaOuToner(item) {
    return TIPOS_TINTA.has(item.tipo) || TIPOS_TONER.has(item.tipo);
}

function corDoItem(item, corantes) {
    for (const t of [corantes[item.corante] || '', item.descricao || '']) {
        const achado = NOMES_COR.find(([en]) => String(t).toLowerCase().includes(en));
        if (achado) return achado[1];
    }
    return null;
}

// nivel -2 = desconhecido, -3 = "há algum restante" (RFC 3805) — sem percentual
function calcularPercentual(max, nivel) {
    if (typeof nivel !== 'number' || nivel < 0) return null;
    let perc;
    if (max > 0) perc = Math.round((nivel / max) * 100);
    else if (max === -2) perc = nivel > 100 ? Math.round((nivel / 255) * 100) : nivel;
    else return null;
    return Math.max(0, Math.min(100, perc));
}

// itens: [{ tipo, corante, descricao, max, nivel }]; corantes: { indice: 'black', ... }
function interpretarSuprimentos(itens, corantes = {}) {
    const porCor = new Map();
    for (const item of itens) {
        if (!ehTintaOuToner(item)) continue;
        const nome = corDoItem(item, corantes);
        if (!nome || porCor.has(nome)) continue;
        const percentual = calcularPercentual(item.max, item.nivel);
        if (percentual !== null) porCor.set(nome, { nome, percentual });
    }
    return ORDEM_CORES.filter(c => porCor.has(c)).map(c => porCor.get(c));
}

// Cores de tinta/toner que a impressora tem, mesmo sem nível legível
function coresDosSuprimentos(itens, corantes = {}) {
    return [...new Set(itens.filter(ehTintaOuToner).map(it => corDoItem(it, corantes)).filter(Boolean))];
}

function normalizarSerie(serie) {
    return String(serie ?? '').trim().toUpperCase();
}

// Aparelho no IP não é o cadastrado: os dois números de série existem e diferem
function serieDivergente(serieCadastrada, serieDetectada) {
    const cadastrada = normalizarSerie(serieCadastrada);
    const detectada  = normalizarSerie(serieDetectada);
    return Boolean(cadastrada && detectada && cadastrada !== detectada);
}

function snmpGet(session, oids) {
    return new Promise(resolve => session.get(oids, (erro, varbinds) => resolve({ erro, varbinds })));
}

async function lerTextoSNMP(session, oid) {
    const { erro, varbinds } = await snmpGet(session, [oid]);
    if (erro || !varbinds?.[0] || snmp.isVarbindError(varbinds[0])) return '';
    return textoSNMP(varbinds[0].value);
}

async function consultarImpressora(ip, comunidade, { timeout = 1000 } = {}) {
    const offline = { online: false, sysDescr: '', modelo: '', serie: '', itens: [], corantes: {} };
    const session = snmp.createSession(ip, comunidade || 'public', { timeout, retries: 1 });
    try {
        // Qualquer resposta — inclusive noSuchName — significa que o aparelho está na rede.
        const inicial = await snmpGet(session, [OID_SYS_DESCR]);
        if (inicial.erro && inicial.erro.name !== 'RequestFailedError') return offline;
        const sysDescr = !inicial.erro && !snmp.isVarbindError(inicial.varbinds[0]) ? textoSNMP(inicial.varbinds[0].value) : '';
        const modelo   = await lerTextoSNMP(session, OID_MODELO);
        const serie    = await lerTextoSNMP(session, OID_NUMERO_SERIE);

        const itens = [];
        for (let i = 1; i <= MAX_ITENS_SUPRIMENTO; i++) {
            const col = c => `${OID_SUPRIMENTOS}.${c}.1.${i}`;
            const { erro, varbinds } = await snmpGet(session, [col(5), col(3), col(6), col(8), col(9)]);
            // noSuchName = a tabela acabou (ou não existe)
            if (erro || varbinds.some(vb => snmp.isVarbindError(vb))) break;
            const [tipo, corante, descricao, max, nivel] = varbinds.map(vb => vb.value);
            itens.push({ tipo, corante, descricao: textoSNMP(descricao), max, nivel });
        }

        const corantes = {};
        const indices = [...new Set(itens.map(it => it.corante).filter(c => c > 0))];
        if (indices.length) {
            const { erro, varbinds } = await snmpGet(session, indices.map(c => `${OID_CORANTES}.${c}`));
            if (!erro) varbinds.forEach((vb, k) => {
                if (!snmp.isVarbindError(vb)) corantes[indices[k]] = textoSNMP(vb.value);
            });
        }
        return { online: true, sysDescr, modelo, serie, itens, corantes };
    } finally {
        session.close();
    }
}

// ── Presença na rede (quando o SNMP não responde) ─────────────────────────────
// Diferencia "desligada / fora da rede" de "ligada, mas sem leitura SNMP"
// (SNMP desativado, comunidade errada ou outro aparelho no IP). Conexão aceita
// ou recusada (RST) nas portas usuais de impressora = há algo ligado no IP;
// sem resposta em todas = nada responde.
const PORTAS_PRESENCA = [9100, 631, 80, 443]; // RAW, IPP, web

function testarPorta(ip, porta, timeout) {
    return new Promise(resolve => {
        const socket = net.connect({ host: ip, port: porta });
        const fim = resultado => { socket.destroy(); resolve(resultado); };
        socket.setTimeout(timeout, () => fim('sem_resposta'));
        socket.once('connect', () => fim('aberta'));
        socket.once('error', e => fim(e.code === 'ECONNREFUSED' ? 'recusada' : 'sem_resposta'));
    });
}

async function verificarPresencaNaRede(ip, { portas = PORTAS_PRESENCA, timeout = 1000 } = {}) {
    const resultados = await Promise.all(portas.map(p => testarPorta(ip, p, timeout)));
    return {
        na_rede: resultados.some(r => r !== 'sem_resposta'),
        portas_abertas: portas.filter((_, i) => resultados[i] === 'aberta')
    };
}

// ── Níveis pela página interna da HP (LEDM) ───────────────────────────────────
// Algumas HP (ex.: LaserJet Pro 4103) respondem "nível desconhecido" no SNMP,
// mas informam o percentual em /DevMgmt/ConsumableConfigDyn.xml. Esse XML
// também revela cartucho recarregado — caso em que a HP não informa o nível.
const CORES_LEDM = { K: 'Preto', C: 'Ciano', M: 'Magenta', Y: 'Amarelo' };
const AVISO_RECARREGADO = 'Cartucho recarregado — a HP não informa o nível de cartuchos recarregados';

function interpretarConsumiveisHP(xml) {
    const porCor = new Map();
    let recarregado = false;
    const blocos = String(xml).match(/<ccdyn:ConsumableInfo>[\s\S]*?<\/ccdyn:ConsumableInfo>/g) || [];
    for (const bruto of blocos) {
        // Dados do cartucho anterior não descrevem o atual
        const bloco = bruto.replace(/<ccdyn:PreviousCartridgeData>[\s\S]*?<\/ccdyn:PreviousCartridgeData>/g, '');
        const campo = nome => new RegExp(`<dd:${nome}>([^<]*)</dd:${nome}>`).exec(bloco)?.[1]?.trim();
        if (!['toner', 'ink'].includes(campo('ConsumableTypeEnum'))) continue;
        if (campo('IsRefilled') === 'true') recarregado = true;
        const perc = Number.parseInt(campo('ConsumablePercentageLevelRemaining'), 10);
        if (Number.isNaN(perc)) continue;
        for (const letra of campo('ConsumableLabelCode') || '') {
            const nome = CORES_LEDM[letra];
            if (nome && !porCor.has(nome)) porCor.set(nome, { nome, percentual: Math.max(0, Math.min(100, perc)) });
        }
    }
    return { suprimentos: ORDEM_CORES.filter(c => porCor.has(c)).map(c => porCor.get(c)), recarregado };
}

function obterConsumiveisHP(ip) {
    return new Promise(resolve => {
        const vazio = { suprimentos: [], recarregado: false };
        const req = http.get({ host: ip, port: 80, path: '/DevMgmt/ConsumableConfigDyn.xml', timeout: 2000 }, res => {
            if (res.statusCode !== 200) { res.resume(); return resolve(vazio); }
            let xml = '';
            res.setEncoding('utf8');
            res.on('data', parte => { if (xml.length < 512 * 1024) xml += parte; });
            res.on('end', () => resolve(interpretarConsumiveisHP(xml)));
        });
        req.on('timeout', () => req.destroy());
        req.on('error', () => resolve(vazio));
    });
}

// ── Página de suprimentos das HP empresariais (FutureSmart) ───────────────────
// HP como a LaserJet E42540 enviam nível 0 pelo SNMP quando NÃO sabem o nível
// (ex.: cartucho de contrato "MC" com garantia encerrada / recarregado), mas a
// própria página de suprimentos mostra "--%". Ela é consultada quando o SNMP
// diz 0%, para não exibir um 0% falso nem gerar alerta de tinta crítica.
const CORES_HP_WEB = { black: 'Preto', cyan: 'Ciano', magenta: 'Magenta', yellow: 'Amarelo' };

// Devolve [{ nome, percentual (null = desconhecido), paginas, garantiaEncerrada }]
function interpretarSuprimentosHPWeb(html) {
    const texto = String(html);
    const garantiaEncerrada = /warranty on this supply has ended|garantia[^.<]*(terminou|encerrad|expirou)/i.test(texto);
    const blocos = texto.split(/<div class="section consumable-block /).slice(1);
    const resultado = [];
    for (const bloco of blocos) {
        const cor = /^consumable-block-(\w+)/.exec(bloco)?.[1];
        const nome = CORES_HP_WEB[cor];
        const percentualTexto = /<p class="data percentage">([^<]*)<\/p>/.exec(bloco)?.[1];
        if (!nome || percentualTexto === undefined) continue;
        const numero = /(\d{1,3})\s*%/.exec(percentualTexto);
        const paginas = Number.parseInt(/-PagesPrintedWithSupply">\s*([\d.,]+)/.exec(bloco)?.[1]?.replace(/[.,]/g, ''), 10);
        resultado.push({
            nome,
            percentual: numero ? Math.min(100, Number(numero[1])) : null,
            paginas: Number.isNaN(paginas) ? null : paginas,
            garantiaEncerrada
        });
    }
    return resultado;
}

function obterSuprimentosHPWeb(ip) {
    return new Promise(resolve => {
        const req = https.get({
            host: ip, path: '/hp/device/InternalPages/Index?id=SuppliesStatus', timeout: 3000,
            rejectUnauthorized: false // certificado autoassinado da própria impressora (somente leitura)
        }, res => {
            if (res.statusCode !== 200) { res.resume(); return resolve([]); }
            let html = '';
            res.setEncoding('utf8');
            res.on('data', parte => { if (html.length < 1024 * 1024) html += parte; });
            res.on('end', () => resolve(interpretarSuprimentosHPWeb(html)));
        });
        req.on('timeout', () => req.destroy());
        req.on('error', () => resolve([]));
    });
}

// Confere com a página da HP os itens que o SNMP deu como 0%
async function conferirZerosHP(ip, suprimentos) {
    const web = await obterSuprimentosHPWeb(ip);
    if (!web.length) return { suprimentos, aviso: null };
    const desconhecidos = [];
    const conferidos = [];
    for (const s of suprimentos) {
        const item = web.find(w => w.nome === s.nome);
        if (s.percentual !== 0 || !item) { conferidos.push(s); continue; }
        if (item.percentual === null) desconhecidos.push(item);
        else conferidos.push({ ...s, percentual: item.percentual });
    }
    if (!desconhecidos.length) return { suprimentos: conferidos, aviso: null };
    const detalhes = desconhecidos.map(d => [
        d.garantiaEncerrada ? 'garantia do cartucho encerrada' : null,
        d.paginas ? `${d.paginas.toLocaleString('pt-BR')} páginas impressas com ele` : null
    ].filter(Boolean).join(', '));
    const cores = desconhecidos.map(d => d.nome).join(', ');
    const aviso = `A HP não informa o nível do toner ${cores}` + (detalhes[0] ? ` (${detalhes[0]})` : '');
    return { suprimentos: conferidos, aviso };
}

// Resposta usada para impressoras USB, que não são consultadas pela rede
const SEM_MONITORAMENTO = Object.freeze({
    online: false, na_rede: false, portas_abertas: [], suprimentos: [], aviso_suprimento: null,
    serie_detectada: null, modelo_detectado: null
});

async function obterDadosSNMP(ip, comunidade) {
    try {
        let c = await consultarImpressora(ip, comunidade);
        // Rede lenta ou pacote perdido: nova tentativa, com mais paciência, antes de
        // dar a impressora como sem resposta (evita alarmes passageiros)
        if (!c.online) c = await consultarImpressora(ip, comunidade, { timeout: 2000 });
        if (!c.online) return { ...SEM_MONITORAMENTO, ...(await verificarPresencaNaRede(ip)) };
        let suprimentos = interpretarSuprimentos(c.itens, c.corantes);
        let aviso_suprimento = null;
        const ehHP = /\bHP\b|hewlett/i.test(`${c.sysDescr} ${c.modelo}`);
        // HP empresarial manda 0 quando não sabe o nível — conferir na página dela
        if (ehHP && suprimentos.some(s => s.percentual === 0)) {
            ({ suprimentos, aviso: aviso_suprimento } = await conferirZerosHP(ip, suprimentos));
        }
        // Nenhum nível legível pela MIB padrão — tentar OID proprietário Brother
        if (suprimentos.length === 0 && !aviso_suprimento) suprimentos = await obterNiveisBrother(ip, comunidade);
        // ...e a página interna da HP (linha Pro)
        if (suprimentos.length === 0 && !aviso_suprimento && ehHP) {
            const hp = await obterConsumiveisHP(ip);
            suprimentos = hp.suprimentos;
            if (!suprimentos.length && hp.recarregado) aviso_suprimento = AVISO_RECARREGADO;
        }
        return {
            online: true,
            na_rede: true,
            portas_abertas: [],
            suprimentos,
            aviso_suprimento,
            serie_detectada: c.serie || null,
            modelo_detectado: c.modelo || c.sysDescr || null
        };
    } catch (e) {
        console.error(`Erro SNMP em ${ip}:`, e.message);
        return { ...SEM_MONITORAMENTO };
    }
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
    db.all("SELECT id, ip, comunidade, numero_serie FROM impressoras WHERE conexao <> 'usb'", [], async (err, rows) => {
        if (err || !rows.length) return;
        const agora = new Date().toISOString();
        for (const imp of rows) {
            const [snmpData, paginas] = await Promise.all([
                obterDadosSNMP(imp.ip, imp.comunidade),
                obterContadorPaginas(imp.ip, imp.comunidade)
            ]);
            db.run('INSERT INTO historico_status (impressora_id, online, registrado_em) VALUES (?, ?, ?)',
                [imp.id, snmpData.online ? 1 : 0, agora]);
            // Primeira leitura grava o nº de série; depois disso, série diferente = aparelho trocado
            if (!normalizarSerie(imp.numero_serie) && snmpData.serie_detectada) {
                db.run('UPDATE impressoras SET numero_serie = ? WHERE id = ?', [snmpData.serie_detectada, imp.id]);
            }
            for (const s of (snmpData.suprimentos || [])) {
                db.run('INSERT INTO historico_tinta (impressora_id, cor, percentual, coletado_em) VALUES (?, ?, ?, ?)',
                    [imp.id, s.nome, s.percentual, agora]);
            }
            if (paginas !== null) {
                db.run('INSERT INTO historico_paginas (impressora_id, paginas_total, coletado_em) VALUES (?, ?, ?)',
                    [imp.id, paginas, agora]);
            }
        }
        await atualizarLeiturasParadas();
    });
}

// ── Leitura não confiável ─────────────────────────────────────────────────────
// Algumas impressoras informam sempre o mesmo nível (ex.: Epson com tinta
// compatível/a granel ou chip que "zera", cartucho de contrato sempre em 0%).
// Se nenhuma cor muda há LEITURA_PARADA_DIAS e a impressora imprimiu ao menos
// LEITURA_PARADA_PAGINAS nesse período, o nível exibido provavelmente não é real.
const LEITURA_PARADA_DIAS    = 14;
const LEITURA_PARADA_PAGINAS = 500;
const SALTO_MAXIMO_CONTADOR  = 50000; // salto maior = contador de outro aparelho (troca no mesmo IP)
const DIA_MS = 24 * 60 * 60 * 1000;

let leiturasParadas = new Map(); // impressora_id → resultado de detectarLeituraParada

// tinta: [{ cor, percentual, em }], paginas: [{ total, em }] — `em` em milissegundos
function detectarLeituraParada(tinta, paginas, agora = Date.now()) {
    if (!tinta.length) return null;
    const ordenadas = [...tinta].sort((a, b) => a.em - b.em);
    const ultimaColeta = ordenadas[ordenadas.length - 1].em;
    const atual = new Map(ordenadas.filter(t => t.em === ultimaColeta).map(t => [t.cor, t.percentual]));

    // O trecho parado começa na mudança mais recente entre todas as cores
    let desde = ordenadas[0].em;
    for (const t of ordenadas) {
        if (atual.has(t.cor) && t.percentual !== atual.get(t.cor) && t.em > desde) desde = t.em;
    }

    let impressas = 0;
    const contadores = paginas.filter(p => p.em >= desde && p.total !== null).sort((a, b) => a.em - b.em);
    for (let i = 1; i < contadores.length; i++) {
        const delta = contadores[i].total - contadores[i - 1].total;
        if (delta > 0 && delta <= SALTO_MAXIMO_CONTADOR) impressas += delta;
    }

    const dias = Math.floor((agora - desde) / DIA_MS);
    if (dias < LEITURA_PARADA_DIAS || impressas < LEITURA_PARADA_PAGINAS) return null;
    return { desde: new Date(desde).toISOString(), dias, paginas: impressas, niveis: Object.fromEntries(atual) };
}

function consultarTodos(sql, params = []) {
    return new Promise((resolve, reject) => db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)));
}

function executar(sql, params = []) {
    return new Promise((resolve, reject) => db.run(sql, params, function (err) { err ? reject(err) : resolve(this); }));
}

// ── Limpeza do histórico antigo ───────────────────────────────────────────────
// A coleta grava ~1 linha por impressora/cor por hora. Retenção com folga sobre
// a maior janela consultada: tinta e status até 180 dias nos relatórios (365 na
// leitura não confiável); páginas até 5 anos (relatório anual).
const RETENCAO_HISTORICO = [
    { tabela: 'historico_tinta',   coluna: 'coletado_em',   dias: 2 * 365 },
    { tabela: 'historico_status',  coluna: 'registrado_em', dias: 2 * 365 },
    { tabela: 'historico_paginas', coluna: 'coletado_em',   dias: 6 * 365 },
];

async function limparHistoricoAntigo(agora = Date.now()) {
    const removidas = {};
    try {
        for (const { tabela, coluna, dias } of RETENCAO_HISTORICO) {
            const limite = new Date(agora - dias * DIA_MS).toISOString();
            removidas[tabela] = (await executar(`DELETE FROM ${tabela} WHERE ${coluna} < ?`, [limite])).changes;
        }
        const total = Object.values(removidas).reduce((a, b) => a + b, 0);
        if (total) console.log('Histórico antigo removido:', removidas);
    } catch (e) {
        console.error('Erro ao limpar histórico antigo:', e.message);
    }
    return removidas;
}

async function atualizarLeiturasParadas() {
    try {
        const limite = new Date(Date.now() - 365 * DIA_MS).toISOString();
        const emMs = r => ({ ...r, em: Date.parse(r.em) });
        const impressoras = await consultarTodos("SELECT id FROM impressoras WHERE conexao <> 'usb'");
        const resultado = new Map();
        for (const { id } of impressoras) {
            const tinta = await consultarTodos(
                'SELECT cor, percentual, coletado_em AS em FROM historico_tinta WHERE impressora_id = ? AND coletado_em >= ?', [id, limite]);
            const paginas = await consultarTodos(
                'SELECT paginas_total AS total, coletado_em AS em FROM historico_paginas WHERE impressora_id = ? AND coletado_em >= ?', [id, limite]);
            const parada = detectarLeituraParada(tinta.map(emMs), paginas.map(emMs));
            if (parada) resultado.set(id, parada);
        }
        leiturasParadas = resultado;
    } catch (e) {
        console.error('Erro ao avaliar leituras paradas:', e.message);
    }
}

// Só vale se a leitura ao vivo continua exatamente nos níveis parados
function leituraSuspeitaAtual(impressoraId, snmpData) {
    const parada = leiturasParadas.get(impressoraId);
    if (!parada || !snmpData.online || !snmpData.suprimentos?.length) return null;
    const iguais = snmpData.suprimentos.every(s => parada.niveis[s.nome] === s.percentual);
    return iguais ? parada : null;
}

// ── Auditoria de impressão por usuário (page_log do CUPS, PRINTSRV/.216) ───────
// Formato da linha (PageLogFormat customizado no PRINTSRV):
// printer|user|job-id|date-time|page-num|copies|job-originating-host-name|job-name
function numeroOuNull(v) {
    // Number(v) || null trataria 0 como ausente -- 0 é valor real (ex.: job_pages.log
    // registra 0 página quando o job nunca chegou a imprimir de fato).
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
}

function parsePageLogLine(linha) {
    // CUPS envolve a linha inteira em aspas quando o PageLogFormat é customizado.
    const semAspas = String(linha).replace(/^"|"$/g, '');
    const campos = semAspas.split('|');
    if (campos.length < 8) return null;
    const [impressora, usuario, jobId, , pagina, copias, hostname, documento] = campos;
    if (!impressora || !usuario) return null;
    return {
        impressora,
        usuario,
        jobId: numeroOuNull(jobId),
        pagina: numeroOuNull(pagina),
        copias: numeroOuNull(copias),
        hostname,
        documento
    };
}

function buscarLogRemoto(caminho, sinceLine) {
    return new Promise((resolve) => {
        const url = `${PAGELOG_API_URL}${caminho}?since_line=${sinceLine}`;
        const req = http.get(url, { headers: { 'X-API-Key': PAGELOG_API_TOKEN }, timeout: 5000 }, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                if (res.statusCode !== 200) return resolve(null);
                try { resolve(JSON.parse(data)); } catch { resolve(null); }
            });
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => req.destroy());
    });
}

function buscarPageLog(sinceLine) {
    return buscarLogRemoto('/api/pagelog', sinceLine);
}

function buscarJobPages(sinceLine) {
    return buscarLogRemoto('/api/jobpages', sinceLine);
}

async function coletarImpressoes() {
    if (!PAGELOG_API_URL || !PAGELOG_API_TOKEN) return;

    const cursor = await new Promise((resolve, reject) => {
        db.get('SELECT last_line, last_line_jobpages FROM impressoes_cursor WHERE id = 1', [],
            (err, row) => err ? reject(err) : resolve(row || { last_line: 0, last_line_jobpages: 0 }));
    });

    const [pageLog, jobPages] = await Promise.all([
        buscarPageLog(cursor.last_line),
        buscarJobPages(cursor.last_line_jobpages)
    ]);

    // job_pages.log (backend SNMP 'pagecount') tem a contagem real de página/cópia.
    // O page_log nativo do CUPS, pra fila raw, grava o literal "total" no lugar do
    // número de página -- nunca conta de verdade. Indexa por impressora+job pra
    // sobrescrever pagina/copias do page_log com o valor real quando existir.
    const contagemReal = new Map();
    if (jobPages && Array.isArray(jobPages.lines)) {
        for (const linha of jobPages.lines) {
            const p = parsePageLogLine(linha);
            if (!p || p.jobId === null) continue;
            contagemReal.set(`${p.impressora}::${p.jobId}`, p);
        }
    }

    if (pageLog && Array.isArray(pageLog.lines)) {
        for (const linha of pageLog.lines) {
            const p = parsePageLogLine(linha);
            if (!p) continue;
            const real = p.jobId !== null ? contagemReal.get(`${p.impressora}::${p.jobId}`) : null;
            const paginas = real ? real.pagina : p.pagina;
            const copias = real ? real.copias : p.copias;
            await new Promise((resolve, reject) => {
                db.run(
                    `INSERT INTO impressoes (impressora, usuario, job_id, paginas, copias, hostname_origem, documento)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [p.impressora, p.usuario, p.jobId, paginas, copias, p.hostname, p.documento],
                    (err) => err ? reject(err) : resolve()
                );
            });
        }
    }

    const novoLastLine = (pageLog && typeof pageLog.total_lines === 'number') ? pageLog.total_lines : cursor.last_line;
    const novoLastLineJobpages = (jobPages && typeof jobPages.total_lines === 'number') ? jobPages.total_lines : cursor.last_line_jobpages;

    if (novoLastLine !== cursor.last_line || novoLastLineJobpages !== cursor.last_line_jobpages) {
        await new Promise((resolve, reject) => {
            db.run('UPDATE impressoes_cursor SET last_line = ?, last_line_jobpages = ? WHERE id = 1',
                [novoLastLine, novoLastLineJobpages], (err) => err ? reject(err) : resolve());
        });
    }
}

// ── Descoberta de dispositivo via SNMP ────────────────────────────────────────
const FABRICANTES = ['Canon', 'HP', 'Epson', 'Brother', 'Kyocera', 'Samsung'];

async function descobrirImpressora(ip) {
    const c = await consultarImpressora(ip, 'public', { timeout: 2000 });
    if (!c.online) {
        return { online: false, fabricante: '', modelo: '', numero_serie: '', tipo: 'Colorido', material: 'Toner', comunidade: 'public' };
    }
    const texto      = `${c.sysDescr} ${c.modelo}`;
    const fabricante = FABRICANTES.find(f => texto.toLowerCase().includes(f.toLowerCase())) || '';
    const tipo       = coresDosSuprimentos(c.itens, c.corantes).some(cor => cor !== 'Preto') ? 'Colorido' : 'Mono';
    const usaTinta   = c.itens.some(it => TIPOS_TINTA.has(it.tipo));
    const usaToner   = c.itens.some(it => TIPOS_TONER.has(it.tipo));
    const material   = usaTinta ? 'Tinta' : usaToner ? 'Toner' : (/laser|toner/i.test(texto) ? 'Toner' : 'Tinta');
    return { online: true, fabricante, modelo: c.modelo || c.sysDescr, numero_serie: c.serie, tipo, material, comunidade: 'public' };
}

// ── Rotas ─────────────────────────────────────────────────────────────────────

app.get('/api/dashboard', exigirAlgumaPermissao(['dashboard', 'estoque']), (req, res, next) => {
    db.all('SELECT id, nome, ip, modelo, localizacao, comunidade, tipo, material, numero_serie, conexao FROM impressoras', [], async (err, rows) => {
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
    db.all('SELECT id, nome AS fabricante, ip, modelo, localizacao, comunidade, tipo, material, numero_serie, conexao FROM impressoras ORDER BY id ASC', [], (err, rows) => {
        if (err) return next(err);
        res.json(rows);
    });
});

app.post('/api/impressoras', exigirPermissao('impressoras'), (req, res, next) => {
    const erros = validarImpressora(req.body, true);
    if (erros.length) return res.status(400).json({ erro: erros.join('; ') });

    const { nome, ip, modelo, localizacao, comunidade, tipo, material, numero_serie } = req.body;
    const conexao = req.body.conexao || 'rede';
    db.run(
        `INSERT INTO impressoras (nome, ip, modelo, localizacao, comunidade, tipo, material, numero_serie, conexao) VALUES (?,?,?,?,?,?,?,?,?)`,
        [nome.trim(), conexao === 'usb' ? null : ip.trim(), modelo.trim(), localizacao?.trim?.() ?? localizacao, comunidade || 'public', tipo || 'Colorido', material || 'Toner', numero_serie?.trim() || null, conexao],
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

    const { nome, modelo, ip, localizacao, comunidade, tipo, material, numero_serie, conexao } = req.body;
    db.get('SELECT * FROM impressoras WHERE id = ?', [req.params.id], (err, existing) => {
        if (err) { console.error(err); return next(err); }
        if (!existing) return res.status(404).json({ erro: 'Impressora não encontrada' });
        const conexaoFinal = conexao ?? existing.conexao ?? 'rede';
        const ipFinal = conexaoFinal === 'usb' ? null : (String(ip ?? existing.ip ?? '').trim() || null);
        if (!ipFinal && conexaoFinal === 'rede') return res.status(400).json({ erro: 'ip é obrigatório para impressora de rede' });
        db.run(
            `UPDATE impressoras SET nome = ?, modelo = ?, ip = ?, localizacao = ?, comunidade = ?, tipo = ?, material = ?, numero_serie = ?, conexao = ? WHERE id = ?`,
            [
                (nome        ?? existing.nome)?.trim?.()    ?? existing.nome,
                (modelo      ?? existing.modelo)?.trim?.()  ?? existing.modelo,
                ipFinal,
                (localizacao ?? existing.localizacao)?.trim?.() ?? existing.localizacao,
                comunidade   ?? existing.comunidade,
                tipo         ?? existing.tipo,
                material     ?? existing.material,
                numero_serie === undefined ? existing.numero_serie : (numero_serie?.trim() || null),
                conexaoFinal,
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
  location.replace('/admin.html');
</script>
</body></html>`);
    } catch (e) {
        console.error('Erro no acoplamento SSO:', e);
        res.status(500).send('Erro interno no acoplamento.');
    }
});

// ── Sessão de admin ───────────────────────────────────────────────────────────
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
    db.all('SELECT id, nome, usuario, perfil, permissoes, ativo, criado_em, ultimo_login FROM usuarios ORDER BY criado_em', [], (err, rows) => {
        if (err) return res.status(500).json({ erro: 'Erro ao listar usuários.' });
        res.json(rows.map(u => ({ ...u, permissoes: normalizarPermissoes(u.permissoes) })));
    });
});

// Cadastro prévio: o login deve ser o mesmo do Gestão. Ao entrar pelo SSO, a
// pessoa já encontra o perfil e as permissões definidos aqui (sem cadastro
// prévio, o SSO cria o usuário como admin).
app.post('/api/usuarios', exigirPermissao('usuarios'), async (req, res) => {
    const { nome, usuario, perfil, permissoes } = req.body;
    if (!nome || !usuario) return res.status(400).json({ erro: 'Nome e usuário são obrigatórios.' });
    const perfilFinal = perfil === 'operador' ? 'operador' : 'admin';
    const permsFinal = perfilFinal === 'admin' ? PERMISSOES_PADRAO : normalizarPermissoes(permissoes);
    try {
        // Senha aleatória e nunca comunicada — a conta só entra via SSO.
        const hash = await hashSenha(crypto.randomBytes(32).toString('hex'));
        db.run(
            `INSERT INTO usuarios (nome, usuario, senha_hash, perfil, permissoes) VALUES (?, ?, ?, ?, ?)`,
            [nome.trim(), usuario.trim().toLowerCase(), hash, perfilFinal, JSON.stringify(permsFinal)],
            function(err) {
                if (err) return res.status(409).json({ erro: 'Usuário já existe.' });
                res.status(201).json({ ok: true, id: this.lastID });
            }
        );
    } catch { res.status(500).json({ erro: 'Erro interno.' }); }
});

app.put('/api/usuarios/:id', exigirPermissao('usuarios'), async (req, res) => {
    const { nome, ativo, perfil, permissoes } = req.body;
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
        if (ehUSB(imp)) return res.status(400).json({ erro: 'Impressora conectada via USB não recebe impressão pela rede' });

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

app.get('/api/descobrir', limiterDescoberta, exigirPermissao('impressoras'), async (req, res, next) => {
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
    db.all('SELECT id, nome, ip, modelo, localizacao, tipo, material, comunidade, numero_serie, conexao FROM impressoras ORDER BY nome ASC', [], async (err, rows) => {
        if (err) return next(err);
        const resultados = await Promise.all(rows.map(async (imp) => {
            const [snmpData, paginas] = ehUSB(imp) ? [SEM_MONITORAMENTO, null] : await Promise.all([
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

// ── Expediente (base da disponibilidade) ──────────────────────────────────────
// As impressoras são desligadas à noite, no fim de semana e (algumas) no
// almoço; medir 24h fazia todas parecerem indisponíveis. A disponibilidade
// considera só seg–sex dentro de EXPEDIENTE ("08-12,14-17" = 8h–12h e 14h–17h),
// no fuso FUSO_HORARIO_HORAS (Fortaleza = -3). O valor 24h segue como referência.
function horasDoExpediente(texto) {
    const horas = new Set();
    for (const faixa of String(texto || '').split(',')) {
        const m = /^\s*(\d{1,2})\s*-\s*(\d{1,2})\s*$/.exec(faixa);
        if (!m) continue;
        for (let h = Number(m[1]); h < Number(m[2]) && h < 24; h++) horas.add(h);
    }
    return [...horas].sort((a, b) => a - b);
}

const HORAS_EXPEDIENTE = (() => {
    const horas = horasDoExpediente(process.env.EXPEDIENTE || '08-12,14-17');
    return horas.length ? horas : horasDoExpediente('08-12,14-17');
})();
const FUSO_HORARIO = `${Number.parseInt(process.env.FUSO_HORARIO_HORAS ?? '-3', 10) || 0} hours`;
const NO_EXPEDIENTE = `(strftime('%w', h.registrado_em, '${FUSO_HORARIO}') BETWEEN '1' AND '5'
    AND CAST(strftime('%H', h.registrado_em, '${FUSO_HORARIO}') AS INTEGER) IN (${HORAS_EXPEDIENTE.join(',')}))`;

app.get('/api/relatorios/disponibilidade', exigirPermissao('relatorios'), (req, res, next) => {
    db.all(
        `SELECT i.id, i.nome, i.ip, i.modelo, i.localizacao,
                SUM(CASE WHEN ${NO_EXPEDIENTE} THEN 1 ELSE 0 END) AS total_checkins,
                SUM(CASE WHEN ${NO_EXPEDIENTE} THEN h.online ELSE 0 END) AS checkins_online,
                CASE WHEN SUM(CASE WHEN ${NO_EXPEDIENTE} THEN 1 ELSE 0 END) = 0 THEN NULL
                     ELSE ROUND(100.0 * SUM(CASE WHEN ${NO_EXPEDIENTE} THEN h.online ELSE 0 END)
                                / SUM(CASE WHEN ${NO_EXPEDIENTE} THEN 1 ELSE 0 END), 1) END AS uptime_pct,
                COUNT(h.id) AS total_checkins_24h,
                CASE WHEN COUNT(h.id) = 0 THEN NULL
                     ELSE ROUND(100.0 * SUM(COALESCE(h.online, 0)) / COUNT(h.id), 1) END AS uptime_24h_pct,
                MAX(CASE WHEN h.online = 0 AND ${NO_EXPEDIENTE} THEN h.registrado_em END) AS ultimo_offline
         FROM impressoras i
         LEFT JOIN historico_status h
                ON h.impressora_id = i.id AND h.registrado_em >= datetime('now', '-30 days')
         WHERE i.conexao <> 'usb'
         GROUP BY i.id ORDER BY uptime_pct ASC, i.nome ASC`,
        [], (err, rows) => {
            if (err) return next(err);
            res.json(rows);
        }
    );
});

app.get('/api/relatorios/auditoria', exigirPermissao('relatorios'), (req, res, next) => {
    const diasPermitidos = new Set([7, 30, 90, 180]);
    const dias = diasPermitidos.has(Number(req.query.dias)) ? Number(req.query.dias) : 7;
    const condicoes = [`registrado_em >= datetime('now', '-${dias} days')`];
    const params = [];
    if (req.query.usuario) {
        condicoes.push('usuario LIKE ?');
        params.push(`%${req.query.usuario}%`);
    }
    if (req.query.impressora) {
        condicoes.push('impressora = ?');
        params.push(req.query.impressora);
    }
    db.all(
        `SELECT impressora, usuario, paginas, copias, hostname_origem, documento, registrado_em
         FROM impressoes
         WHERE ${condicoes.join(' AND ')}
         ORDER BY registrado_em DESC
         LIMIT 500`,
        params,
        (err, rows) => {
            if (err) return next(err);
            res.json({ total: rows.length, registros: rows });
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

module.exports = { app, db, dbReady, estoqueTokens, parsePageLogLine, coletarImpressoes, interpretarSuprimentos, serieDivergente, verificarPresencaNaRede, interpretarConsumiveisHP, interpretarSuprimentosHPWeb,
    detectarLeituraParada, atualizarLeiturasParadas, limparHistoricoAntigo, horasDoExpediente };

// ── Inicialização e graceful shutdown (apenas quando executado diretamente) ────
if (require.main === module) {
    const PORT   = process.env.PORT || 3000;
    const server = app.listen(PORT, () => console.log(`Servidor em http://localhost:${PORT}`));

    dbReady.then(() => {
        limparHistoricoAntigo();
        setInterval(limparHistoricoAntigo, 24 * 60 * 60 * 1000).unref();
        atualizarLeiturasParadas();
        coletarHistorico();
        setInterval(coletarHistorico, 60 * 60 * 1000).unref();

        if (PAGELOG_API_URL && PAGELOG_API_TOKEN) {
            coletarImpressoes();
            setInterval(coletarImpressoes, 5 * 60 * 1000).unref();
        }
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
