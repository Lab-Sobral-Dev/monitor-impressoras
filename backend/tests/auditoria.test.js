'use strict';

const request = require('supertest');
const { app, db, dbReady } = require('../server');
const { entrarViaSSO } = require('./sso');

function runDB(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, err => err ? reject(err) : resolve());
    });
}

function limparImpressoes() {
    return new Promise((resolve, reject) => {
        db.run('DELETE FROM impressoes', err => err ? reject(err) : resolve());
    });
}

async function obterTokenAdmin() {
    return (await entrarViaSSO(app)).token;
}

async function authAdmin() {
    return { Authorization: `Bearer ${await obterTokenAdmin()}` };
}

function isoAgora(offsetDias = 0) {
    return new Date(Date.now() + offsetDias * 86400000).toISOString().slice(0, 19).replace('T', ' ');
}

function inserirImpressao({ impressora, usuario, paginas, copias = 1, hostname_origem = 'LABTI01', documento = 'doc.pdf', offsetDias = 0 }) {
    return runDB(
        `INSERT INTO impressoes (impressora, usuario, job_id, paginas, copias, hostname_origem, documento, registrado_em)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [impressora, usuario, 1, paginas, copias, hostname_origem, documento, isoAgora(offsetDias)]
    );
}

beforeAll(() => dbReady);
beforeEach(() => limparImpressoes());
afterAll(() => new Promise(resolve => db.close(resolve)));

describe('GET /api/relatorios/auditoria', () => {
    it('deve retornar 401 sem token', async () => {
        const res = await request(app).get('/api/relatorios/auditoria');
        expect(res.status).toBe(401);
    });

    it('deve retornar 403 quando usuário não tem permissão de relatorios', async () => {
        const usuario = `teste.semperm.${Date.now()}`;
        await request(app)
            .post('/api/usuarios')
            .set(await authAdmin())
            .send({ nome: 'Sem Permissao', usuario, perfil: 'operador', permissoes: ['dashboard'] });
        const sessao = await entrarViaSSO(app, usuario);

        const res = await request(app)
            .get('/api/relatorios/auditoria')
            .set('Authorization', `Bearer ${sessao.token}`);
        expect(res.status).toBe(403);
    });

    it('deve listar impressões dentro do período default (7 dias), mais recentes primeiro', async () => {
        await inserirImpressao({ impressora: 'PIXMA130', usuario: 'jsilva', paginas: 3, offsetDias: -1 });
        await inserirImpressao({ impressora: 'PIXMA130', usuario: 'pmiranda', paginas: 1, offsetDias: 0 });

        const res = await request(app)
            .get('/api/relatorios/auditoria')
            .set(await authAdmin());

        expect(res.status).toBe(200);
        expect(res.body.total).toBe(2);
        expect(res.body.registros[0].usuario).toBe('pmiranda');
        expect(res.body.registros[1].usuario).toBe('jsilva');
    });

    it('não deve incluir registros fora do período pedido', async () => {
        await inserirImpressao({ impressora: 'PIXMA130', usuario: 'antigo', paginas: 5, offsetDias: -30 });

        const res = await request(app)
            .get('/api/relatorios/auditoria?dias=7')
            .set(await authAdmin());

        expect(res.status).toBe(200);
        expect(res.body.total).toBe(0);
    });

    it('deve filtrar por usuario', async () => {
        await inserirImpressao({ impressora: 'PIXMA130', usuario: 'jsilva', paginas: 3 });
        await inserirImpressao({ impressora: 'PIXMA130', usuario: 'pmiranda', paginas: 1 });

        const res = await request(app)
            .get('/api/relatorios/auditoria?usuario=jsilva')
            .set(await authAdmin());

        expect(res.status).toBe(200);
        expect(res.body.total).toBe(1);
        expect(res.body.registros[0].usuario).toBe('jsilva');
    });

    it('deve filtrar por impressora', async () => {
        await inserirImpressao({ impressora: 'PIXMA130', usuario: 'jsilva', paginas: 3 });
        await inserirImpressao({ impressora: 'OUTRA', usuario: 'jsilva', paginas: 2 });

        const res = await request(app)
            .get('/api/relatorios/auditoria?impressora=OUTRA')
            .set(await authAdmin());

        expect(res.status).toBe(200);
        expect(res.body.total).toBe(1);
        expect(res.body.registros[0].impressora).toBe('OUTRA');
    });

    it('deve retornar array vazio quando não há registros', async () => {
        const res = await request(app)
            .get('/api/relatorios/auditoria')
            .set(await authAdmin());

        expect(res.status).toBe(200);
        expect(res.body.total).toBe(0);
        expect(res.body.registros).toEqual([]);
    });
});
