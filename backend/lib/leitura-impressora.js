'use strict';

// Leitura das impressoras pela rede: SNMP (Printer-MIB), páginas internas da
// HP (LEDM e FutureSmart), teste de presença na rede e descoberta por IP.
// Não depende do banco nem das rotas — só recebe IP/comunidade e devolve dados.
const snmp  = require('net-snmp');
const net   = require('net');
const http  = require('http');
const https = require('https');

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

module.exports = {
    obterDadosSNMP,
    obterContadorPaginas,
    descobrirImpressora,
    verificarPresencaNaRede,
    interpretarSuprimentos,
    interpretarConsumiveisHP,
    interpretarSuprimentosHPWeb,
    normalizarSerie,
    serieDivergente,
    SEM_MONITORAMENTO
};
