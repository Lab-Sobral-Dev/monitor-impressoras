// tests/leitura.test.js
'use strict';

// Detecção de leitura não confiável: nível parado apesar de muitas páginas impressas
const { detectarLeituraParada, limparHistoricoAntigo, db, dbReady } = require('../server');

afterAll(() => dbReady.then(() => new Promise(resolve => db.close(resolve))));

const DIA = 24 * 60 * 60 * 1000;
const AGORA = Date.parse('2026-10-15T12:00:00Z');
const CORES = ['Preto', 'Ciano', 'Magenta', 'Amarelo'];

// Uma coleta por dia, de `dias` atrás até hoje; nivel(dia, cor) e contador(dia) definem os valores
function historico(dias, nivel, contador) {
    const tinta = [];
    const paginas = [];
    for (let d = dias; d >= 0; d--) {
        const em = AGORA - d * DIA;
        for (const cor of CORES) tinta.push({ cor, percentual: nivel(d, cor), em });
        paginas.push({ total: contador(d), em });
    }
    return { tinta, paginas };
}

describe('detectarLeituraParada', () => {
    it('acusa nível parado em 100% com milhares de páginas impressas (Epson da Recepção)', () => {
        const { tinta, paginas } = historico(60, () => 100, d => 90000 - d * 50);
        expect(detectarLeituraParada(tinta, paginas, AGORA)).toEqual({
            desde: new Date(AGORA - 60 * DIA).toISOString(),
            dias: 60,
            paginas: 3000,
            niveis: { Preto: 100, Ciano: 100, Magenta: 100, Amarelo: 100 }
        });
    });

    it('não acusa impressora cujo nível desce normalmente', () => {
        const { tinta, paginas } = historico(60, d => 40 + Math.floor(d / 3), d => 90000 - d * 50);
        expect(detectarLeituraParada(tinta, paginas, AGORA)).toBeNull();
    });

    it('não acusa impressora parada que quase não imprimiu', () => {
        const { tinta, paginas } = historico(60, () => 80, d => 5000 - d * 2);
        expect(detectarLeituraParada(tinta, paginas, AGORA)).toBeNull();
    });

    it('não acusa antes de completar o prazo mínimo sem mudança', () => {
        // Mudou há 10 dias e imprimiu bastante desde então
        const { tinta, paginas } = historico(60, d => (d > 10 ? 90 : 100), d => 90000 - d * 200);
        expect(detectarLeituraParada(tinta, paginas, AGORA)).toBeNull();
    });

    it('basta uma cor mudar para não considerar parado', () => {
        const { tinta, paginas } = historico(60, (d, cor) => (cor === 'Ciano' && d > 3 ? 70 : 100), d => 90000 - d * 50);
        expect(detectarLeituraParada(tinta, paginas, AGORA)).toBeNull();
    });

    it('ignora o salto de contador quando o aparelho é trocado no mesmo IP', () => {
        // Contador saltou de ~3.000 para ~180.000 no dia 30 (outro aparelho); só 20 páginas/dia de verdade
        const { tinta, paginas } = historico(60, () => 100, d => (d > 30 ? 3000 : 180000) - d * 20);
        const r = detectarLeituraParada(tinta, paginas, AGORA);
        expect(r.paginas).toBe(1200 - 20);
    });

    it('sem histórico de tinta não há o que avaliar', () => {
        expect(detectarLeituraParada([], [], AGORA)).toBeNull();
    });
});

describe('limparHistoricoAntigo', () => {
    const run = (sql, p = []) => new Promise((ok, erro) => db.run(sql, p, e => e ? erro(e) : ok()));
    const contar = (tabela) => new Promise((ok, erro) =>
        db.get(`SELECT COUNT(*) AS n FROM ${tabela} WHERE impressora_id = 999`, [], (e, r) => e ? erro(e) : ok(r.n)));
    const haDias = d => new Date(AGORA - d * DIA).toISOString();

    beforeAll(async () => {
        await dbReady;
        for (const d of [10, 400, 800]) {
            await run('INSERT INTO historico_tinta (impressora_id, cor, percentual, coletado_em) VALUES (999, ?, 50, ?)', ['Preto', haDias(d)]);
            await run('INSERT INTO historico_status (impressora_id, online, registrado_em) VALUES (999, 1, ?)', [haDias(d)]);
        }
        for (const d of [10, 3 * 365, 7 * 365]) {
            await run('INSERT INTO historico_paginas (impressora_id, paginas_total, coletado_em) VALUES (999, 100, ?)', [haDias(d)]);
        }
    });

    it('remove tinta/status com mais de 2 anos e páginas com mais de 6 anos', async () => {
        const removidas = await limparHistoricoAntigo(AGORA);
        expect(removidas).toEqual({ historico_tinta: 1, historico_status: 1, historico_paginas: 1 });
        expect(await contar('historico_tinta')).toBe(2);
        expect(await contar('historico_status')).toBe(2);
        // 3 anos de páginas continuam: o relatório anual consulta até 5 anos
        expect(await contar('historico_paginas')).toBe(2);
    });
});
