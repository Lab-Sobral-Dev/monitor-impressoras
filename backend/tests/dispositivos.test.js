// tests/dispositivos.test.js
'use strict';

// Tela de Dispositivos: cadastro/edição/remoção e envio de impressão
const request = require('supertest');
const { app, db, dbReady } = require('../server');
const { entrarViaSSO } = require('./sso');

const run = (sql, p = []) => new Promise((ok, erro) => db.run(sql, p, e => e ? erro(e) : ok()));
const contar = (sql, p = []) => new Promise((ok, erro) => db.get(sql, p, (e, r) => e ? erro(e) : ok(r.n)));

async function auth() {
    return { Authorization: `Bearer ${(await entrarViaSSO(app)).token}` };
}

async function cadastrar(dados) {
    return request(app).post('/api/impressoras').set(await auth())
        .send({ nome: 'HP', modelo: 'HP LaserJet Pro MFP 4103fdw', localizacao: 'Financeiro', ...dados });
}

beforeAll(() => dbReady);
beforeEach(async () => {
    for (const t of ['impressoras', 'historico_tinta', 'historico_paginas', 'historico_status', 'trocas_toner']) await run(`DELETE FROM ${t}`);
});
afterAll(() => new Promise(resolve => db.close(resolve)));

describe('IP duplicado', () => {
    it('não cadastra duas impressoras de rede no mesmo IP', async () => {
        expect((await cadastrar({ ip: '192.168.1.32' })).status).toBe(201);
        const res = await cadastrar({ ip: '192.168.1.32', localizacao: 'PCP' });
        expect(res.status).toBe(409);
        expect(res.body.erro).toMatch(/192\.168\.1\.32.*Financeiro/);
    });

    it('não deixa a edição colocar o IP de outra impressora, mas aceita manter o próprio', async () => {
        await cadastrar({ ip: '192.168.1.32' });
        await cadastrar({ ip: '192.168.1.77', localizacao: 'PCP' });
        const lista = (await request(app).get('/api/impressoras').set(await auth())).body;
        const pcp = lista.find(p => p.localizacao === 'PCP');

        const conflito = await request(app).put(`/api/impressoras/${pcp.id}`).set(await auth()).send({ ip: '192.168.1.32' });
        expect(conflito.status).toBe(409);

        const mesmo = await request(app).put(`/api/impressoras/${pcp.id}`).set(await auth()).send({ ip: '192.168.1.77', localizacao: 'PCP/Compras' });
        expect(mesmo.status).toBe(200);
    });

    it('impressoras USB não entram na regra (não têm IP)', async () => {
        expect((await cadastrar({ conexao: 'usb' })).status).toBe(201);
        expect((await cadastrar({ conexao: 'usb', localizacao: 'Micro' })).status).toBe(201);
    });
});

describe('tipo, material e comunidade', () => {
    it('edição aceita trocar tipo, material e comunidade', async () => {
        await cadastrar({ ip: '192.168.1.20' });
        const [{ id }] = (await request(app).get('/api/impressoras').set(await auth())).body;
        const res = await request(app).put(`/api/impressoras/${id}`).set(await auth())
            .send({ tipo: 'Mono', material: 'Toner', comunidade: 'interna' });
        expect(res.status).toBe(200);
        const [imp] = (await request(app).get('/api/impressoras').set(await auth())).body;
        expect(imp).toMatchObject({ tipo: 'Mono', material: 'Toner', comunidade: 'interna' });
    });

    it('recusa valores fora da lista', async () => {
        const res = await cadastrar({ ip: '192.168.1.21', tipo: 'Laser', material: 'Cera' });
        expect(res.status).toBe(400);
        expect(res.body.erro).toMatch(/tipo/);
        expect(res.body.erro).toMatch(/material/);
    });
});

describe('DELETE /api/impressoras/:id', () => {
    it('remove também o histórico da impressora', async () => {
        await cadastrar({ ip: '192.168.1.32' });
        const [{ id }] = (await request(app).get('/api/impressoras').set(await auth())).body;
        await run('INSERT INTO historico_tinta (impressora_id, cor, percentual) VALUES (?, ?, ?)', [id, 'Preto', 40]);
        await run('INSERT INTO historico_paginas (impressora_id, paginas_total) VALUES (?, ?)', [id, 1000]);
        await run('INSERT INTO historico_status (impressora_id, online) VALUES (?, 1)', [id]);

        const res = await request(app).delete(`/api/impressoras/${id}`).set(await auth());
        expect(res.status).toBe(204);
        for (const t of ['historico_tinta', 'historico_paginas', 'historico_status']) {
            expect(await contar(`SELECT COUNT(*) AS n FROM ${t} WHERE impressora_id = ?`, [id])).toBe(0);
        }
    });

    it('responde 404 para impressora inexistente', async () => {
        const res = await request(app).delete('/api/impressoras/99999').set(await auth());
        expect(res.status).toBe(404);
    });
});

describe('POST /api/impressoras/:id/imprimir', () => {
    it('impressora que recusa conexão: responde erro uma única vez, sem derrubar o servidor', async () => {
        // 127.0.0.1 sem nada nas portas 631/9100 recusa na hora (IPP, IPP e RAW falham)
        await cadastrar({ ip: '127.0.0.1' });
        const [{ id }] = (await request(app).get('/api/impressoras').set(await auth())).body;
        const res = await request(app).post(`/api/impressoras/${id}/imprimir`).set(await auth()).send({ conteudo: 'teste' });
        expect(res.status).toBe(502);
        expect(res.body.erro).toBeTruthy();
        // o servidor continua respondendo
        expect((await request(app).get('/api/impressoras').set(await auth())).status).toBe(200);
    });
});
