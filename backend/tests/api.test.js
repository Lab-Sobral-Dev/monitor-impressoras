'use strict';

jest.mock('net-snmp', () => ({
    createSession: () => ({
        get: (_oids, cb) => cb(new Error('mocked')),
        close: () => {}
    })
}));

const request = require('supertest');
const { app, db, dbReady, estoqueTokens } = require('../server');

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
    const res = await request(app)
        .post('/api/auth/login')
        .send({ usuario: 'admin', senha: 'admin-de-teste' });
    return res.body.token;
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

    it('deve permitir alterar senha de usuario e liberar login sem troca obrigatoria', async () => {
        const usuario = `teste.senha.${Date.now()}`;
        const criado = await request(app)
            .post('/api/usuarios')
            .set(await authAdmin())
            .send({ nome: 'Teste Senha', usuario, senha: 'senha123' });
        expect(criado.status).toBe(201);

        const lista = await request(app).get('/api/usuarios').set(await authAdmin());
        const user = lista.body.find(u => u.usuario === usuario);

        const upd = await request(app)
            .put(`/api/usuarios/${user.id}`)
            .set(await authAdmin())
            .send({ senha: 'nova123', trocar_senha: false });
        expect(upd.status).toBe(200);

        const login = await request(app)
            .post('/api/auth/login')
            .send({ usuario, senha: 'nova123' });
        expect(login.status).toBe(200);
        expect(login.body.ok).toBe(true);
        expect(login.body.trocar_senha).toBeUndefined();
        expect(login.body.token).toBeTruthy();
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
        const lista = await request(app).get('/api/usuarios').set(await authAdmin());
        const user = lista.body.find(u => u.usuario === usuario);
        await request(app)
            .put(`/api/usuarios/${user.id}`)
            .set(await authAdmin())
            .send({ trocar_senha: false });

        const login = await request(app)
            .post('/api/auth/login')
            .send({ usuario, senha: 'senha123' });
        expect(login.status).toBe(200);
        expect(login.body.permissoes).toEqual(['relatorios']);

        const negado = await request(app)
            .get('/api/usuarios')
            .set('Authorization', `Bearer ${login.body.token}`);
        expect(negado.status).toBe(403);

        const permitido = await request(app)
            .get('/api/relatorios/disponibilidade')
            .set('Authorization', `Bearer ${login.body.token}`);
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
        const id = await criarImpressora();
        const res = await request(app).put(`/api/impressoras/${id}`).set(await authAdmin()).send({ localizacao: 'Recepção' });
        expect(res.status).toBe(200);
        expect(res.body.sucesso).toBe(true);
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
