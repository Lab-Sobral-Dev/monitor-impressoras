// tests/paginas-ao-vivo.test.js
'use strict';

// Ao abrir o relatório de páginas, o contador é lido na hora (sem esperar a
// coleta horária) e gravado se mudou.
let mockContador = 5130;

jest.mock('net-snmp', () => ({
    createSession: () => ({
        get: (_oids, cb) => cb(null, [{ value: mockContador }]),
        close: () => {}
    }),
    isVarbindError: () => false
}));

const request = require('supertest');
const { app, db, dbReady } = require('../server');
const { entrarViaSSO } = require('./sso');

const run = (sql, p = []) => new Promise((ok, erro) => db.run(sql, p, e => e ? erro(e) : ok()));
const contarLeituras = () => new Promise((ok, erro) =>
    db.get('SELECT COUNT(*) AS n FROM historico_paginas WHERE impressora_id = 1', [], (e, r) => e ? erro(e) : ok(r.n)));

beforeAll(async () => {
    await dbReady;
    await run(`INSERT INTO impressoras (id, nome, ip, modelo, conexao) VALUES (1, 'Canon', '192.168.1.130', 'Canon MF650C Series', 'rede')`);
    await run('INSERT INTO historico_paginas (impressora_id, paginas_total, coletado_em) VALUES (1, 5125, ?)',
        [new Date(Date.now() - 30 * 60 * 1000).toISOString()]);
});
afterAll(() => new Promise(resolve => db.close(resolve)));

describe('GET /api/relatorios/paginas/:id — contador ao vivo', () => {
    it('inclui a impressão feita depois da última coleta horária', async () => {
        const { token } = await entrarViaSSO(app);
        const res = await request(app).get('/api/relatorios/paginas/1?periodo=hora').set('Authorization', `Bearer ${token}`);
        expect(res.body.total_atual).toBe(5130);
        expect(res.body.periodos.reduce((a, p) => a + p.paginas_impressas, 0)).toBe(5);
        expect(await contarLeituras()).toBe(2);
    });

    it('não grava leitura repetida quando o contador não mudou', async () => {
        const { token } = await entrarViaSSO(app);
        await request(app).get('/api/relatorios/paginas/1?periodo=hora').set('Authorization', `Bearer ${token}`);
        expect(await contarLeituras()).toBe(2);
    });
});
