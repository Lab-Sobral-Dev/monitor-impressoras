// tests/paginas.test.js
'use strict';

// Relatório de páginas impressas a partir do contador total (coleta horária)
const request = require('supertest');
const { app, db, dbReady } = require('../server');
const { paginasPorPeriodo } = require('../lib/analise-historico');
const { entrarViaSSO } = require('./sso');

const HORA = 60 * 60 * 1000;
const run = (sql, p = []) => new Promise((ok, erro) => db.run(sql, p, e => e ? erro(e) : ok()));

beforeAll(() => dbReady);
afterAll(() => new Promise(resolve => db.close(resolve)));

describe('paginasPorPeriodo', () => {
    // Fortaleza (-3): 2026-10-14 08:40 local = 11:40Z
    const em = iso => Date.parse(iso);

    it('visão por hora: cada leitura horária gera a diferença da hora (antes ficava sempre vazia)', () => {
        const leituras = [
            { total: 1000, em: em('2026-10-14T11:40:00Z') },
            { total: 1010, em: em('2026-10-14T12:40:00Z') },
            { total: 1030, em: em('2026-10-14T13:40:00Z') },
        ];
        expect(paginasPorPeriodo(leituras, 'hora', -3)).toEqual([
            { periodo: '2026-10-14T09:00', paginas_impressas: 10 },
            { periodo: '2026-10-14T10:00', paginas_impressas: 20 },
        ]);
    });

    it('não perde as páginas entre o último registro de um dia e o primeiro do seguinte', () => {
        const leituras = [
            { total: 500, em: em('2026-10-13T19:40:00Z') }, // 16:40 local
            { total: 520, em: em('2026-10-14T11:40:00Z') }, // 08:40 local do dia seguinte
            { total: 530, em: em('2026-10-14T19:40:00Z') },
        ];
        // Cálculo antigo (maior − menor por dia) daria 10 no dia 14 e perderia as 20 da virada
        expect(paginasPorPeriodo(leituras, 'dia', -3)).toEqual([{ periodo: '2026-10-14', paginas_impressas: 30 }]);
    });

    it('corta o dia à meia-noite local, não em UTC', () => {
        const leituras = [
            { total: 100, em: em('2026-10-14T23:00:00Z') }, // 20:00 local do dia 14
            { total: 105, em: em('2026-10-15T00:30:00Z') }, // 21:30 local — ainda dia 14
        ];
        expect(paginasPorPeriodo(leituras, 'dia', -3)).toEqual([{ periodo: '2026-10-14', paginas_impressas: 5 }]);
    });

    it('ignora o salto de contador da troca de aparelho e contadores que voltam', () => {
        const leituras = [
            { total: 3000, em: em('2026-10-10T12:00:00Z') },
            { total: 3020, em: em('2026-10-11T12:00:00Z') },
            { total: 180000, em: em('2026-10-12T12:00:00Z') }, // outro aparelho no IP
            { total: 180050, em: em('2026-10-13T12:00:00Z') },
            { total: 0, em: em('2026-10-14T12:00:00Z') },      // leitura zerada
        ];
        expect(paginasPorPeriodo(leituras, 'mes', -3)).toEqual([{ periodo: '2026-10', paginas_impressas: 70 }]);
    });

    it('leituras antes do início da janela só servem de base', () => {
        const leituras = [
            { total: 100, em: em('2026-09-29T12:00:00Z') },
            { total: 150, em: em('2026-10-01T12:00:00Z') },
            { total: 160, em: em('2026-10-02T12:00:00Z') },
        ];
        const r = paginasPorPeriodo(leituras, 'dia', -3, em('2026-10-01T00:00:00Z'));
        expect(r).toEqual([
            { periodo: '2026-10-01', paginas_impressas: 50 },
            { periodo: '2026-10-02', paginas_impressas: 10 },
        ]);
    });
});

describe('GET /api/relatorios/paginas/:id', () => {
    it('soma as diferenças horárias e informa o contador mais recente', async () => {
        await run('DELETE FROM historico_paginas WHERE impressora_id = 777');
        const agora = Date.now();
        const leituras = [
            [5000, agora - 40 * 24 * HORA], // fora da janela de 30 dias: só base
            [5100, agora - 5 * HORA],
            [5110, agora - 4 * HORA],
            [5110, agora - 3 * HORA],
            [5125, agora - 2 * HORA],
        ];
        for (const [total, quando] of leituras) {
            await run('INSERT INTO historico_paginas (impressora_id, paginas_total, coletado_em) VALUES (777, ?, ?)',
                [total, new Date(quando).toISOString()]);
        }
        const { token } = await entrarViaSSO(app);
        const total = r => r.body.periodos.reduce((a, p) => a + p.paginas_impressas, 0);
        const hora = await request(app).get('/api/relatorios/paginas/777?periodo=hora').set('Authorization', `Bearer ${token}`);
        expect(hora.status).toBe(200);
        expect(hora.body.total_atual).toBe(5125);
        expect(total(hora)).toBe(25);

        // A leitura de 40 dias atrás está longe demais para atribuir as 100 páginas a um dia
        const dia = await request(app).get('/api/relatorios/paginas/777?periodo=dia').set('Authorization', `Bearer ${token}`);
        expect(total(dia)).toBe(25);
    });
});

describe('paginasPorPeriodo — lacunas', () => {
    it('conta a virada do fim de semana, mas não uma lacuna de semanas', () => {
        const em = iso => Date.parse(iso);
        const leituras = [
            { total: 100, em: em('2026-10-09T20:40:00Z') }, // sexta 17:40
            { total: 112, em: em('2026-10-12T11:40:00Z') }, // segunda 08:40 (≈ 2,6 dias depois)
            { total: 500, em: em('2026-11-02T11:40:00Z') }, // 3 semanas sem leitura
        ];
        expect(paginasPorPeriodo(leituras, 'dia', -3)).toEqual([{ periodo: '2026-10-12', paginas_impressas: 12 }]);
        // Na visão mensal, a lacuna de 3 semanas cabe e as páginas entram
        expect(paginasPorPeriodo(leituras, 'mes', -3)).toEqual([
            { periodo: '2026-10', paginas_impressas: 12 },
            { periodo: '2026-11', paginas_impressas: 388 },
        ]);
    });
});
