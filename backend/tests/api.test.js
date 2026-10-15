'use strict';

jest.mock('net-snmp', () => ({
    createSession: () => ({
        get: (_oids, cb) => cb(new Error('mocked')),
        close: () => {}
    })
}));

const request = require('supertest');
const { app, db, dbReady, estoqueTokens } = require('../server');
const { assinarTokenAcoplamento, entrarViaSSO } = require('./sso');

const IMP_VALIDA = { nome: 'Canon MF654', ip: '192.168.1.10', modelo: 'MF654Cdw', localizacao: 'Sala TI' };

function limparDB() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.run('DELETE FROM impressoras', err => { if (err) return reject(err); });
            db.run('DELETE FROM estoque', err => { if (err) return reject(err); });
            db.run('DELETE FROM historico_tinta', err => { if (err) return reject(err); });
            db.run('DELETE FROM trocas_toner', err => { if (err) return reject(err); });
            db.run('SELECT 1', resolve);
        });
    });
}

async function obterToken() {
    const res = await request(app)
        .post('/api/auth/estoque')
        .send({ senha: 'senha-de-teste' });
    return res.body.token;
}

async function obterTokenAdmin() {
    return (await entrarViaSSO(app)).token;
}

async function authAdmin() {
    return { Authorization: `Bearer ${await obterTokenAdmin()}` };
}

function runDB(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, err => err ? reject(err) : resolve());
    });
}

async function criarImpressora(dados = IMP_VALIDA) {
    const res = await request(app).post('/api/impressoras').set(await authAdmin()).send(dados);
    const lista = await request(app).get('/api/estoque').set(await authAdmin());
    // busca id via dashboard mock (offline), então consultamos direto
    return new Promise((resolve, reject) => {
        db.get('SELECT id FROM impressoras ORDER BY id DESC LIMIT 1', (err, row) => {
            if (err) return reject(err);
            resolve(row.id);
        });
    });
}

beforeAll(() => dbReady);
beforeEach(() => limparDB());
afterAll(() => new Promise(resolve => db.close(resolve)));

// ── POST /api/auth/estoque ────────────────────────────────────────────────────
describe('POST /api/auth/estoque', () => {
    it('deve retornar 401 quando senha incorreta', async () => {
        const res = await request(app)
            .post('/api/auth/estoque')
            .send({ senha: 'errada' });
        expect(res.status).toBe(401);
        expect(res.body.ok).toBe(false);
    });

    it('deve retornar 200 e token quando senha correta', async () => {
        const res = await request(app)
            .post('/api/auth/estoque')
            .send({ senha: 'senha-de-teste' });
        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
        expect(typeof res.body.token).toBe('string');
        expect(res.body.token.length).toBeGreaterThan(0);
    });

    it('deve retornar 400 quando senha não enviada', async () => {
        const res = await request(app)
            .post('/api/auth/estoque')
            .send({});
        expect(res.status).toBe(400);
    });
});

// ── Entrada pelo Gestão (SSO) ─────────────────────────────────────────────────
describe('GET /api/auth/sso', () => {
    it('deve abrir sessão de admin com token válido do Gestão', async () => {
        const sessao = await entrarViaSSO(app, `teste.sso.${Date.now()}`);
        expect(sessao.perfil).toBe('admin');
        expect(typeof sessao.token).toBe('string');

        const res = await request(app).get('/api/auth/verify').set('Authorization', `Bearer ${sessao.token}`);
        expect(res.status).toBe(200);
        expect(res.body.ok).toBe(true);
    });

    it('deve recusar token com assinatura inválida', async () => {
        const token = assinarTokenAcoplamento({ sub: 'intruso' }, 'segredo-errado');
        const res = await request(app).get('/api/auth/sso').query({ token });
        expect(res.status).toBe(401);
    });

    it('deve recusar token expirado', async () => {
        const token = assinarTokenAcoplamento({ sub: 'atrasado', exp: Math.floor(Date.now() / 1000) - 1 });
        const res = await request(app).get('/api/auth/sso').query({ token });
        expect(res.status).toBe(401);
    });

    it('deve recusar usuário desativado', async () => {
        const usuario = `teste.inativo.${Date.now()}`;
        await entrarViaSSO(app, usuario);
        await runDB('UPDATE usuarios SET ativo = 0 WHERE usuario = ?', [usuario]);
        const res = await request(app).get('/api/auth/sso').query({ token: assinarTokenAcoplamento({ sub: usuario }) });
        expect(res.status).toBe(401);
    });
});

describe('Login por usuário e senha', () => {
    it('não deve existir mais (entrada só pelo Gestão)', async () => {
        const res = await request(app).post('/api/auth/login').send({ usuario: 'admin', senha: 'qualquer' });
        expect(res.status).toBe(404);
    });
});

describe('Gestao de usuarios', () => {
    it('deve listar especificacoes de acesso sem expor hash de senha', async () => {
        const usuario = `teste.acesso.${Date.now()}`;
        await request(app)
            .post('/api/usuarios')
            .set(await authAdmin())
            .send({ nome: 'Teste Acesso', usuario, senha: 'senha123' });

        const res = await request(app).get('/api/usuarios').set(await authAdmin());
        expect(res.status).toBe(200);
        const user = res.body.find(u => u.usuario === usuario);
        expect(user).toBeTruthy();
        expect(user).toHaveProperty('trocar_senha');
        expect(user).toHaveProperty('ultimo_login');
        expect(user).not.toHaveProperty('senha_hash');
    });

    it('deve aplicar permissoes por usuario nas rotas protegidas', async () => {
        const usuario = `teste.perm.${Date.now()}`;
        await request(app)
            .post('/api/usuarios')
            .set(await authAdmin())
            .send({
                nome: 'Teste Permissao',
                usuario,
                senha: 'senha123',
                perfil: 'operador',
                permissoes: ['relatorios']
            });
        const sessao = await entrarViaSSO(app, usuario);
        expect(sessao.permissoes).toEqual(['relatorios']);

        const negado = await request(app)
            .get('/api/usuarios')
            .set('Authorization', `Bearer ${sessao.token}`);
        expect(negado.status).toBe(403);

        const permitido = await request(app)
            .get('/api/relatorios/disponibilidade')
            .set('Authorization', `Bearer ${sessao.token}`);
        expect(permitido.status).toBe(200);
    });
});

// ── POST /api/impressoras ─────────────────────────────────────────────────────
describe('GET /api/relatorios/trocas-toner', () => {
    it('deve identificar troca de toner e informar a impressora', async () => {
        const token = await obterTokenAdmin();
        const id = await criarImpressora({ ...IMP_VALIDA, nome: 'Printer Troca', ip: '192.168.1.44' });

        await runDB(
            `INSERT INTO historico_tinta (impressora_id, cor, percentual, coletado_em) VALUES
             (?, 'Preto', 12, datetime('now', '-2 days')),
             (?, 'Preto', 88, datetime('now', '-1 days'))`,
            [id, id]
        );

        const res = await request(app)
            .get('/api/relatorios/trocas-toner?dias=7')
            .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(200);
        expect(res.body.total).toBe(1);
        expect(res.body.eventos[0]).toMatchObject({
            impressora_id: id,
            nome: 'Printer Troca',
            cor: 'Preto',
            percentual_anterior: 12,
            percentual_atual: 88
        });
    });

    it('deve registrar troca manual e listar como registro real', async () => {
        const token = await obterTokenAdmin();
        const id = await criarImpressora({ ...IMP_VALIDA, nome: 'Printer Manual', ip: '192.168.1.45' });

        const criado = await request(app)
            .post('/api/relatorios/trocas-toner')
            .set('Authorization', `Bearer ${token}`)
            .send({
                impressora_id: id,
                cor: 'Ciano',
                percentual_anterior: 8,
                percentual_novo: 100,
                observacao: 'Troca feita pela equipe'
            });

        expect(criado.status).toBe(201);
        expect(criado.body.sucesso).toBe(true);

        const res = await request(app)
            .get('/api/relatorios/trocas-toner?dias=7')
            .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(200);
        expect(res.body.total_manual).toBe(1);
        expect(res.body.eventos[0]).toMatchObject({
            origem: 'manual',
            nome: 'Printer Manual',
            cor: 'Ciano',
            observacao: 'Troca feita pela equipe'
        });
    });
});

describe('POST /api/impressoras', () => {
    it('deve retornar 201 quando dados válidos', async () => {
        const res = await request(app).post('/api/impressoras').set(await authAdmin()).send(IMP_VALIDA);
        expect(res.status).toBe(201);
        expect(res.body.sucesso).toBe(true);
    });

    it('deve retornar 400 quando nome ausente', async () => {
        const res = await request(app).post('/api/impressoras').set(await authAdmin()).send({ ...IMP_VALIDA, nome: '' });
        expect(res.status).toBe(400);
        expect(res.body.erro).toMatch(/nome/);
    });

    it('deve retornar 400 quando ip inválido', async () => {
        const res = await request(app).post('/api/impressoras').set(await authAdmin()).send({ ...IMP_VALIDA, ip: '999.0.0.1' });
        expect(res.status).toBe(400);
        expect(res.body.erro).toMatch(/ip/);
    });

    it('deve retornar 400 quando ip é texto livre', async () => {
        const res = await request(app).post('/api/impressoras').set(await authAdmin()).send({ ...IMP_VALIDA, ip: 'nao-e-um-ip' });
        expect(res.status).toBe(400);
    });

    it('deve retornar 400 quando modelo ausente', async () => {
        const res = await request(app).post('/api/impressoras').set(await authAdmin()).send({ ...IMP_VALIDA, modelo: '' });
        expect(res.status).toBe(400);
        expect(res.body.erro).toMatch(/modelo/);
    });

    it('deve gravar o número de série e devolvê-lo na listagem', async () => {
        const res = await request(app).post('/api/impressoras').set(await authAdmin())
            .send({ ...IMP_VALIDA, numero_serie: ' BRBSP970FP ' });
        expect(res.status).toBe(201);
        const lista = await request(app).get('/api/impressoras').set(await authAdmin());
        expect(lista.body.find(p => p.ip === IMP_VALIDA.ip).numero_serie).toBe('BRBSP970FP');
    });

    it('deve retornar 400 quando número de série não é texto', async () => {
        const res = await request(app).post('/api/impressoras').set(await authAdmin()).send({ ...IMP_VALIDA, numero_serie: 123 });
        expect(res.status).toBe(400);
        expect(res.body.erro).toMatch(/numero_serie/);
    });
});

// ── PUT /api/impressoras/:id ──────────────────────────────────────────────────
describe('PUT /api/impressoras/:id', () => {
    it('deve retornar 404 quando id não existe', async () => {
        const res = await request(app).put('/api/impressoras/9999').set(await authAdmin()).send({ nome: 'X' });
        expect(res.status).toBe(404);
    });

    it('deve retornar 400 quando ip enviado é inválido', async () => {
        const id = await criarImpressora();
        const res = await request(app).put(`/api/impressoras/${id}`).set(await authAdmin()).send({ ip: '300.0.0.1' });
        expect(res.status).toBe(400);
    });

    it('deve retornar 200 e preservar campos não enviados', async () => {
        const id = await criarImpressora({ ...IMP_VALIDA, numero_serie: 'KNDX03073' });
        const res = await request(app).put(`/api/impressoras/${id}`).set(await authAdmin()).send({ localizacao: 'Recepção' });
        expect(res.status).toBe(200);
        expect(res.body.sucesso).toBe(true);
        const lista = await request(app).get('/api/impressoras').set(await authAdmin());
        expect(lista.body.find(p => p.id === id)).toMatchObject({ localizacao: 'Recepção', numero_serie: 'KNDX03073' });
    });

    it('deve trocar e limpar o número de série', async () => {
        const id = await criarImpressora({ ...IMP_VALIDA, numero_serie: 'KNDX03073' });
        await request(app).put(`/api/impressoras/${id}`).set(await authAdmin()).send({ numero_serie: 'XBJX038395' });
        let lista = await request(app).get('/api/impressoras').set(await authAdmin());
        expect(lista.body.find(p => p.id === id).numero_serie).toBe('XBJX038395');

        await request(app).put(`/api/impressoras/${id}`).set(await authAdmin()).send({ numero_serie: '' });
        lista = await request(app).get('/api/impressoras').set(await authAdmin());
        expect(lista.body.find(p => p.id === id).numero_serie).toBeNull();
    });
});

// ── DELETE /api/impressoras/:id ───────────────────────────────────────────────
describe('DELETE /api/impressoras/:id', () => {
    it('deve retornar 404 quando id não existe', async () => {
        const res = await request(app).delete('/api/impressoras/9999').set(await authAdmin());
        expect(res.status).toBe(404);
    });

    it('deve retornar 204 quando impressora existe', async () => {
        const id = await criarImpressora();
        const res = await request(app).delete(`/api/impressoras/${id}`).set(await authAdmin());
        expect(res.status).toBe(204);
    });
});

// ── POST /api/estoque ─────────────────────────────────────────────────────────
describe('POST /api/estoque', () => {
    it('deve retornar 401 sem token', async () => {
        const res = await request(app)
            .post('/api/estoque')
            .send({ modelo: 'X', insumo: 'Preto', quantidade: 5, estado: 'Novo' });
        expect(res.status).toBe(401);
    });

    it('deve retornar 401 com token expirado', async () => {
        const token = await obterToken();
        estoqueTokens.set(token, Date.now() - 1);
        const res = await request(app)
            .post('/api/estoque')
            .set('Authorization', `Bearer ${token}`)
            .send({ modelo: 'X', insumo: 'Preto', quantidade: 5, estado: 'Novo' });
        expect(res.status).toBe(401);
    });

    it('deve retornar 201 quando dados válidos e token correto', async () => {
        const res = await request(app)
            .post('/api/estoque')
            .set(await authAdmin())
            .send({ modelo: 'MF654', insumo: 'Preto', quantidade: 3, estado: 'Novo' });
        expect(res.status).toBe(201);
        expect(res.body.sucesso).toBe(true);
    });

    it('deve retornar 400 quando modelo ausente', async () => {
        const res = await request(app)
            .post('/api/estoque')
            .set(await authAdmin())
            .send({ insumo: 'Preto', quantidade: 3, estado: 'Novo' });
        expect(res.status).toBe(400);
        expect(res.body.erro).toMatch(/modelo/);
    });

    it('deve retornar 400 quando insumo ausente', async () => {
        const res = await request(app)
            .post('/api/estoque')
            .set(await authAdmin())
            .send({ modelo: 'MF654', quantidade: 3, estado: 'Novo' });
        expect(res.status).toBe(400);
        expect(res.body.erro).toMatch(/insumo/);
    });

    it('deve retornar 400 quando quantidade ausente', async () => {
        const res = await request(app)
            .post('/api/estoque')
            .set(await authAdmin())
            .send({ modelo: 'MF654', insumo: 'Preto', estado: 'Novo' });
        expect(res.status).toBe(400);
        expect(res.body.erro).toMatch(/quantidade/);
    });

    it('deve retornar 400 quando quantidade é negativa', async () => {
        const res = await request(app)
            .post('/api/estoque')
            .set(await authAdmin())
            .send({ modelo: 'MF654', insumo: 'Preto', quantidade: -1, estado: 'Novo' });
        expect(res.status).toBe(400);
    });

    it('deve retornar 400 quando quantidade é texto', async () => {
        const res = await request(app)
            .post('/api/estoque')
            .set(await authAdmin())
            .send({ modelo: 'MF654', insumo: 'Preto', quantidade: 'abc', estado: 'Novo' });
        expect(res.status).toBe(400);
    });
});

// ── DELETE /api/estoque/:id ───────────────────────────────────────────────────
describe('DELETE /api/estoque/:id', () => {
    it('deve retornar 401 sem token', async () => {
        const res = await request(app).delete('/api/estoque/1');
        expect(res.status).toBe(401);
    });

    it('deve retornar 404 quando item não existe', async () => {
        const res = await request(app)
            .delete('/api/estoque/9999')
            .set(await authAdmin());
        expect(res.status).toBe(404);
    });
});

// ── GET /api/dashboard ────────────────────────────────────────────────────────
describe('GET /api/dashboard', () => {
    it('deve retornar array vazio quando não há impressoras', async () => {
        const res = await request(app).get('/api/dashboard').set(await authAdmin());
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        expect(res.body).toHaveLength(0);
    });

    it('deve retornar impressoras com campo online', async () => {
        await criarImpressora();
        const res = await request(app).get('/api/dashboard').set(await authAdmin());
        expect(res.status).toBe(200);
        expect(res.body).toHaveLength(1);
        expect(res.body[0]).toHaveProperty('online');
        expect(res.body[0]).toHaveProperty('suprimentos');
    });
});

// ── GET /api/estoque ──────────────────────────────────────────────────────────
describe('GET /api/estoque', () => {
    it('deve retornar array com autenticação', async () => {
        const res = await request(app).get('/api/estoque').set(await authAdmin());
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
    });
});

// ── GET /api/auth/sso — Protocolo de Acoplamento (Gestão) ─────────────────────
describe('GET /api/auth/sso', () => {
    const SEGREDO = process.env.DOCKING_SECRET_MONITOR_IMPRESSORAS;

    function base64url(input) {
        return Buffer.from(input).toString('base64url');
    }

    function criarTokenAcoplamento(overrides = {}, segredo = SEGREDO) {
        const header = { alg: 'HS256', typ: 'JWT' };
        const payload = {
            sub: 'pmiranda',
            produto: 'monitor-impressoras',
            email: 'pmiranda@laboratoriosobral.com.br',
            exp: Math.floor(Date.now() / 1000) + 60,
            ...overrides
        };
        const headerB64  = base64url(JSON.stringify(header));
        const payloadB64 = base64url(JSON.stringify(payload));
        const assinatura = require('crypto')
            .createHmac('sha256', segredo)
            .update(`${headerB64}.${payloadB64}`)
            .digest('base64url');
        return `${headerB64}.${payloadB64}.${assinatura}`;
    }

    function contarUsuario(usuario) {
        return new Promise((resolve, reject) => {
            db.get('SELECT COUNT(*) AS total FROM usuarios WHERE usuario = ?', [usuario], (err, row) => {
                if (err) return reject(err);
                resolve(row.total);
            });
        });
    }

    beforeEach(() => new Promise((resolve, reject) => {
        db.run('DELETE FROM usuarios WHERE usuario = ?', ['pmiranda'], err => err ? reject(err) : resolve());
    }));

    it('deve retornar 400 sem token', async () => {
        const res = await request(app).get('/api/auth/sso');
        expect(res.status).toBe(400);
    });

    it('deve retornar 401 com assinatura inválida', async () => {
        const token = criarTokenAcoplamento({}, 'segredo-errado');
        const res = await request(app).get('/api/auth/sso').query({ token });
        expect(res.status).toBe(401);
    });

    it('deve retornar 401 com token expirado', async () => {
        const token = criarTokenAcoplamento({ exp: Math.floor(Date.now() / 1000) - 10 });
        const res = await request(app).get('/api/auth/sso').query({ token });
        expect(res.status).toBe(401);
    });

    it('deve retornar 401 quando o produto do claim não confere', async () => {
        const token = criarTokenAcoplamento({ produto: 'outro-produto' });
        const res = await request(app).get('/api/auth/sso').query({ token });
        expect(res.status).toBe(401);
    });

    it('deve auto-provisionar o usuário e devolver sessão válida no primeiro acesso', async () => {
        expect(await contarUsuario('pmiranda')).toBe(0);
        const token = criarTokenAcoplamento();
        const res = await request(app).get('/api/auth/sso').query({ token });
        expect(res.status).toBe(200);
        expect(res.text).toContain("sessionStorage.setItem('ic_token'");
        expect(res.text).toContain('pmiranda');
        expect(await contarUsuario('pmiranda')).toBe(1);
    });

    it('não deve duplicar usuário em acessos seguintes', async () => {
        await request(app).get('/api/auth/sso').query({ token: criarTokenAcoplamento() });
        await request(app).get('/api/auth/sso').query({ token: criarTokenAcoplamento() });
        expect(await contarUsuario('pmiranda')).toBe(1);
    });

    it('deve retornar 503 quando o acoplamento não está configurado', async () => {
        let resposta;
        await jest.isolateModulesAsync(async () => {
            const original = process.env.DOCKING_SECRET_MONITOR_IMPRESSORAS;
            delete process.env.DOCKING_SECRET_MONITOR_IMPRESSORAS;
            const isolado = require('../server');
            await isolado.dbReady;
            resposta = await request(isolado.app).get('/api/auth/sso').query({ token: 'qualquer' });
            await new Promise(resolve => isolado.db.close(resolve));
            process.env.DOCKING_SECRET_MONITOR_IMPRESSORAS = original;
        });
        expect(resposta.status).toBe(503);
    });
});
