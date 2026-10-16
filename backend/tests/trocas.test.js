// tests/trocas.test.js
'use strict';

// Relatório de trocas de toner: subida de nível no momento em que outro
// aparelho passou a responder no IP não é troca de toner.
const request = require('supertest');
const { app, db, dbReady } = require('../server');
const { entrarViaSSO } = require('./sso');

const run = (sql, p = []) => new Promise((ok, erro) => db.run(sql, p, e => e ? erro(e) : ok()));
const HORA = 60 * 60 * 1000;
const quando = horasAtras => new Date(Date.now() - horasAtras * HORA).toISOString();

beforeAll(async () => {
    await dbReady;
    await run(`INSERT INTO impressoras (id, nome, ip, modelo, conexao) VALUES
        (1, 'Canon', '192.168.1.92', 'Canon GX6000', 'rede'), (2, 'Canon', '192.168.1.13', 'Canon GX7000', 'rede')`);
    for (const id of [1, 2]) {
        await run('INSERT INTO historico_tinta (impressora_id, cor, percentual, coletado_em) VALUES (?, ?, ?, ?)', [id, 'Preto', 20, quando(30)]);
        await run('INSERT INTO historico_tinta (impressora_id, cor, percentual, coletado_em) VALUES (?, ?, ?, ?)', [id, 'Preto', 100, quando(29)]);
    }
    // Impressora 1: o contador despencou junto (outro aparelho no IP); impressora 2: contador normal
    await run('INSERT INTO historico_paginas (impressora_id, paginas_total, coletado_em) VALUES (1, 181735, ?), (1, 69, ?)', [quando(30), quando(29)]);
    await run('INSERT INTO historico_paginas (impressora_id, paginas_total, coletado_em) VALUES (2, 15000, ?), (2, 15040, ?)', [quando(30), quando(29)]);
});
afterAll(() => new Promise(resolve => db.close(resolve)));

describe('GET /api/relatorios/trocas-toner', () => {
    it('não conta como troca de toner a subida causada por troca de aparelho', async () => {
        const { token } = await entrarViaSSO(app);
        const res = await request(app).get('/api/relatorios/trocas-toner?dias=7').set('Authorization', `Bearer ${token}`);
        expect(res.status).toBe(200);
        expect(res.body.eventos.map(e => e.impressora_id)).toEqual([2]);
    });
});

describe('coleta de status', () => {
    it('status corrigido: offline com contador lido conta como online na disponibilidade', async () => {
        // Simula a correção do script: 'online' quando o contador respondeu na mesma coleta
        const em = quando(5);
        await run('INSERT INTO historico_status (impressora_id, online, registrado_em) VALUES (2, 0, ?)', [em]);
        await run('INSERT INTO historico_paginas (impressora_id, paginas_total, coletado_em) VALUES (2, 15100, ?)', [em]);
        await run(`UPDATE historico_status SET online = 1 WHERE online = 0 AND EXISTS (SELECT 1 FROM historico_paginas p
                   WHERE p.impressora_id = historico_status.impressora_id AND p.coletado_em = historico_status.registrado_em)`);
        const linha = await new Promise((ok, erro) => db.get('SELECT online FROM historico_status WHERE registrado_em = ?', [em], (e, r) => e ? erro(e) : ok(r)));
        expect(linha.online).toBe(1);
    });
});
