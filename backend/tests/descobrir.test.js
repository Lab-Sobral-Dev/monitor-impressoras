// tests/descobrir.test.js
'use strict';

// Agente SNMP v1 simulado: responde só os OIDs que a "impressora" tem; um OID
// inexistente derruba a requisição inteira com noSuchName, como no aparelho real.
let mockAgente = null; // null = impressora não responde (timeout)

function mockErroSNMP(name, message) {
    const e = new Error(message);
    e.name = name;
    return e;
}

jest.mock('net-snmp', () => ({
    createSession: () => ({
        get: (oids, cb) => {
            if (!mockAgente) return cb(mockErroSNMP('RequestTimedOutError', 'Request timed out'));
            const faltando = oids.find(oid => !(oid in mockAgente));
            if (faltando) return cb(mockErroSNMP('RequestFailedError', `NoSuchName: ${faltando}`));
            cb(null, oids.map(oid => ({ oid, value: mockAgente[oid] })));
        },
        close: () => {}
    }),
    isVarbindError: () => false
}));

const request  = require('supertest');
const { app, db, dbReady } = require('../server');
const { entrarViaSSO } = require('./sso');

// A descoberta exige login com permissão de impressoras
async function descobrir(consulta = '') {
    const { token } = await entrarViaSSO(app);
    return request(app).get('/api/descobrir' + consulta).set('Authorization', `Bearer ${token}`);
}

const SUP = '1.3.6.1.2.1.43.11.1.1';

// Monta as respostas de uma impressora: identificação + tabela de suprimentos
function impressora({ descr, modelo, serie, suprimentos = [], corantes = {} }) {
    const agente = { '1.3.6.1.2.1.1.1.0': Buffer.from(descr) };
    if (modelo) agente['1.3.6.1.2.1.25.3.2.1.3.1'] = Buffer.from(modelo);
    if (serie)  agente['1.3.6.1.2.1.43.5.1.1.17.1'] = Buffer.from(serie);
    suprimentos.forEach((s, k) => {
        const i = k + 1;
        agente[`${SUP}.5.1.${i}`] = s.tipo;
        agente[`${SUP}.3.1.${i}`] = s.corante;
        agente[`${SUP}.6.1.${i}`] = Buffer.from(s.descricao);
        agente[`${SUP}.8.1.${i}`] = s.max;
        agente[`${SUP}.9.1.${i}`] = s.nivel;
    });
    for (const [idx, nome] of Object.entries(corantes)) agente[`1.3.6.1.2.1.43.12.1.1.4.1.${idx}`] = Buffer.from(nome);
    return agente;
}

const CANON_COLORIDA = impressora({
    descr: 'Canon MF650C Series /P', modelo: 'Canon MF650C Series', serie: 'YPS12781',
    suprimentos: [
        { tipo: 21, corante: 1, descricao: 'Canon Cartridge 067 Black Toner',   max: 100, nivel: 40 },
        { tipo: 21, corante: 2, descricao: 'Canon Cartridge 067 Cyan Toner',    max: 100, nivel: 88 },
        { tipo: 21, corante: 3, descricao: 'Canon Cartridge 067 Magenta Toner', max: 100, nivel: 79 },
        { tipo: 21, corante: 4, descricao: 'Canon Cartridge 067 Yellow Toner',  max: 100, nivel: 78 },
    ],
    corantes: { 1: 'black', 2: 'cyan', 3: 'magenta', 4: 'yellow' }
});

const HP_MONO = impressora({
    descr: 'HP ETHERNET MULTI-ENVIRONMENT', modelo: 'HP LaserJet Pro MFP 4103fdw', serie: 'BRBSR520T0',
    suprimentos: [{ tipo: 3, corante: 1, descricao: 'Black Cartridge HP W1030XC', max: 100, nivel: -2 }],
    corantes: { 1: 'Black Cartridge' }
});

const EPSON_TINTA = impressora({
    descr: 'EPSON Built-in 11b/g/n & 10/100/1000 Print Server', modelo: 'EPSON WF-C5790 Series', serie: 'X3B7005142',
    suprimentos: [
        { tipo: 5, corante: 1, descricao: 'Black Ink Supply Unit',   max: 100, nivel: 100 },
        { tipo: 5, corante: 2, descricao: 'Cyan Ink Supply Unit',    max: 100, nivel: 100 },
        { tipo: 5, corante: 3, descricao: 'Magenta Ink Supply Unit', max: 100, nivel: 100 },
        { tipo: 5, corante: 4, descricao: 'Yellow Ink Supply Unit',  max: 100, nivel: 100 },
    ],
    corantes: { 1: 'black', 2: 'cyan', 3: 'magenta', 4: 'yellow' }
});

const SAMSUNG_MONO = impressora({
    descr: 'Samsung SL-M4070FR; V4.00.02.18', modelo: 'Samsung M337x 387x 407x Series', serie: 'ZDDPB07K913WRZY',
    suprimentos: [
        { tipo: 3,  corante: 1, descricao: 'Black Toner Cartridge', max: 15000, nivel: 14550 },
        { tipo: 15, corante: 0, descricao: 'Fuser',                 max: 90000, nivel: 89556 },
    ],
    corantes: { 1: 'Black' }
});

beforeAll(() => dbReady);
afterAll(() => new Promise(resolve => db.close(resolve)));
afterEach(() => { mockAgente = null; });

describe('GET /api/descobrir', () => {
    it('deve exigir login (antes era a única rota aberta)', async () => {
        const res = await request(app).get('/api/descobrir?ip=192.168.1.50');
        expect(res.status).toBe(401);
    });

    it('deve retornar 400 quando ip ausente', async () => {
        const res = await descobrir('');
        expect(res.status).toBe(400);
        expect(res.body.erro).toMatch(/IP/i);
    });

    it('deve retornar 400 quando ip inválido', async () => {
        const res = await descobrir('?ip=999.0.0.1');
        expect(res.status).toBe(400);
        expect(res.body.erro).toMatch(/IP/i);
    });

    it('deve retornar online:false e campos vazios quando SNMP não responde', async () => {
        const res = await descobrir('?ip=192.168.1.50');
        expect(res.status).toBe(200);
        expect(res.body.online).toBe(false);
        expect(res.body.fabricante).toBe('');
        expect(res.body.modelo).toBe('');
        expect(res.body.numero_serie).toBe('');
    });

    it('deve detectar fabricante Canon, tipo Colorido, Toner e o número de série', async () => {
        mockAgente = CANON_COLORIDA;
        const res = await descobrir('?ip=192.168.1.50');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({
            online: true, fabricante: 'Canon', modelo: 'Canon MF650C Series',
            numero_serie: 'YPS12781', tipo: 'Colorido', material: 'Toner'
        });
    });

    it('deve detectar impressora monocromática (antes falhava: OIDs de cor inexistentes derrubavam a consulta)', async () => {
        mockAgente = HP_MONO;
        const res = await descobrir('?ip=192.168.1.50');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ online: true, fabricante: 'HP', tipo: 'Mono', material: 'Toner', numero_serie: 'BRBSR520T0' });
    });

    it('deve detectar material Tinta pelo tipo de suprimento', async () => {
        mockAgente = EPSON_TINTA;
        const res = await descobrir('?ip=192.168.1.50');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ fabricante: 'Epson', tipo: 'Colorido', material: 'Tinta' });
    });

    it('deve detectar Samsung mono sem confundir fusor com cor', async () => {
        mockAgente = SAMSUNG_MONO;
        const res = await descobrir('?ip=192.168.1.50');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ fabricante: 'Samsung', tipo: 'Mono', material: 'Toner', numero_serie: 'ZDDPB07K913WRZY' });
    });

    it('deve usar o texto do modelo quando a impressora não tem tabela de suprimentos', async () => {
        mockAgente = impressora({ descr: 'Brother HL-L2350DW laser', modelo: 'Brother HL-L2350DW' });
        const res = await descobrir('?ip=192.168.1.50');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ online: true, fabricante: 'Brother', tipo: 'Mono', material: 'Toner', numero_serie: '' });
    });
});
