// tests/estoque-ligacao.test.js
'use strict';

// Ligação impressora ↔ estoque: qual grupo do estoque abastece cada impressora
const request = require('supertest');
const { app, db, dbReady, modeloDeEstoque } = require('../server');
const { entrarViaSSO } = require('./sso');

const run = (sql, p = []) => new Promise((ok, erro) => db.run(sql, p, e => e ? erro(e) : ok()));

async function auth() {
    return { Authorization: `Bearer ${(await entrarViaSSO(app)).token}` };
}

beforeAll(() => dbReady);
beforeEach(async () => {
    await run('DELETE FROM impressoras');
    await run('DELETE FROM estoque');
    await run('DELETE FROM historico_tinta');
});
afterAll(() => new Promise(resolve => db.close(resolve)));

describe('modeloDeEstoque', () => {
    it('usa o grupo escolhido no cadastro', () => {
        expect(modeloDeEstoque({ modelo: 'Canon GX7000 series 3.010', material: 'Tinta', estoque_modelo: 'Canon GX7010' }))
            .toBe('Canon GX7010');
    });

    it('Canon GX de tinta caem no grupo compartilhado "Canon GX6010 / GX7010"', () => {
        expect(modeloDeEstoque({ modelo: 'Canon GX7000 series 3.010', material: 'Tinta' })).toBe('Canon GX6010 / GX7010');
        expect(modeloDeEstoque({ modelo: 'Canon  gx7010', material: 'Tinta' })).toBe('Canon GX6010 / GX7010');
    });

    it('demais impressoras usam o próprio modelo (espaços normalizados)', () => {
        expect(modeloDeEstoque({ modelo: ' HP LaserJet  Pro MFP 4103fdw ', material: 'Toner' })).toBe('HP LaserJet Pro MFP 4103fdw');
    });
});

describe('estoque no cadastro e no painel', () => {
    const USB_GX = { nome: 'Canon', modelo: 'Canon GX7000 series 3.010', localizacao: 'RH', conexao: 'usb', tipo: 'Colorido', material: 'Tinta' };

    it('painel mostra o estoque do grupo que abastece a impressora', async () => {
        await run(`INSERT INTO estoque (modelo, insumo, quantidade, estado) VALUES
            ('Canon GX6010 / GX7010', 'Preto', 1, 'Novo'), ('Canon GX6010 / GX7010', 'Ciano', 13, 'Novo'),
            ('Canon GX7010', 'Preto', 4, 'Novo')`);
        await request(app).post('/api/impressoras').set(await auth()).send(USB_GX);

        const res = await request(app).get('/api/dashboard').set(await auth());
        expect(res.body[0]).toMatchObject({
            estoque_modelo_efetivo: 'Canon GX6010 / GX7010',
            estoque: { Preto: 1, Ciano: 13 }
        });
    });

    it('trocar o grupo de estoque no cadastro muda o que o painel mostra', async () => {
        await run(`INSERT INTO estoque (modelo, insumo, quantidade, estado) VALUES ('Canon GX7010', 'Preto', 4, 'Novo')`);
        await request(app).post('/api/impressoras').set(await auth()).send(USB_GX);
        const [{ id }] = (await request(app).get('/api/impressoras').set(await auth())).body;

        await request(app).put(`/api/impressoras/${id}`).set(await auth()).send({ estoque_modelo: 'Canon GX7010' });
        const lista = await request(app).get('/api/impressoras').set(await auth());
        expect(lista.body[0].estoque_modelo).toBe('Canon GX7010');

        const res = await request(app).get('/api/dashboard').set(await auth());
        expect(res.body[0].estoque).toEqual({ Preto: 4 });
    });

    it('lista os grupos de estoque existentes para escolha', async () => {
        await run(`INSERT INTO estoque (modelo, insumo, quantidade, estado) VALUES
            ('Canon GX7010', 'Preto', 4, 'Novo'), ('Canon GX7010', 'Ciano', 2, 'Novo'), ('Brother DCP-T820DW', 'Preto', 1, 'Novo')`);
        const res = await request(app).get('/api/estoque/modelos').set(await auth());
        expect(res.body).toEqual(['Brother DCP-T820DW', 'Canon GX7010']);
    });
});

describe('GET /api/dashboard — pedidos simultâneos', () => {
    it('quem chega durante a atualização recebe a lista completa, não vazia', async () => {
        await run(`INSERT INTO impressoras (nome, modelo, material, conexao) VALUES
            ('HP', 'HP LaserJet Pro MFP 4103fdw', 'Toner', 'usb'), ('Canon', 'Canon GX7000 series 3.010', 'Tinta', 'usb')`);
        // Cadastro via API invalida o cache: os dois pedidos abaixo chegam com o painel vazio
        await request(app).post('/api/impressoras').set(await auth())
            .send({ nome: 'Brother', modelo: 'Brother DCP-T820DW', conexao: 'usb', material: 'Tinta' });
        const cabecalho = await auth();
        const [a, b] = await Promise.all([
            request(app).get('/api/dashboard').set(cabecalho),
            request(app).get('/api/dashboard').set(cabecalho)
        ]);
        expect(a.body).toHaveLength(3);
        expect(b.body).toHaveLength(3);
    });
});

describe('arquivos da tela', () => {
    it('são servidos com Cache-Control: no-cache (navegador sempre confere se mudou)', async () => {
        const res = await request(app).get('/admin-auth.js');
        expect(res.headers['cache-control']).toBe('no-cache');
    });
});

describe('GET /api/relatorios/estoque', () => {
    it('soma o consumo só das impressoras abastecidas pelo grupo (antes misturava todos os modelos)', async () => {
        await run(`INSERT INTO estoque (modelo, insumo, quantidade, estado) VALUES
            ('Brother DCP-T820DW', 'Preto', 2, 'Novo'), ('Kyocera ECOSYS M2040dn', 'Preto', 1, 'Novo')`);
        await run(`INSERT INTO impressoras (id, nome, modelo, material, conexao) VALUES
            (1, 'Brother', 'Brother DCP-T820DW', 'Tinta', 'usb'), (2, 'Kyocera', 'Kyocera ECOSYS M2040dn', 'Toner', 'usb')`);
        const dia = d => new Date(Date.now() - d * 24 * 60 * 60 * 1000).toISOString();
        // Brother: cai 2 pontos/dia; Kyocera: cai 10 pontos/dia
        for (let d = 10; d >= 0; d--) {
            await run('INSERT INTO historico_tinta (impressora_id, cor, percentual, coletado_em) VALUES (1, ?, ?, ?)', ['Preto', 80 - 2 * (10 - d), dia(d)]);
            await run('INSERT INTO historico_tinta (impressora_id, cor, percentual, coletado_em) VALUES (2, ?, ?, ?)', ['Preto', 100 - 10 * (10 - d), dia(d)]);
        }
        const res = await request(app).get('/api/relatorios/estoque').set(await auth());
        const brother = res.body.find(r => r.modelo === 'Brother DCP-T820DW');
        const kyocera = res.body.find(r => r.modelo === 'Kyocera ECOSYS M2040dn');
        expect(brother).toMatchObject({ estoque_atual: 2, impressoras: 1, consumo_dia_medio: 2, dias_estimados: 100 });
        expect(kyocera).toMatchObject({ estoque_atual: 1, impressoras: 1, consumo_dia_medio: 10, dias_estimados: 10 });
    });
});
