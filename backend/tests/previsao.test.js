// tests/previsao.test.js
'use strict';

// Previsão de quando a tinta/toner acaba, a partir do histórico de níveis
const { preverFimDosSuprimentos, previsaoAindaValida, db, dbReady } = require('../server');

afterAll(() => dbReady.then(() => new Promise(resolve => db.close(resolve))));

const DIA = 24 * 60 * 60 * 1000;
const AGORA = Date.parse('2026-10-15T12:00:00Z');

// Uma leitura por dia, de `dias` atrás até hoje, com nivel(diasAtras)
function serie(cor, dias, nivel) {
    return Array.from({ length: dias + 1 }, (_, i) => {
        const diasAtras = dias - i;
        return { cor, percentual: nivel(diasAtras), em: AGORA - diasAtras * DIA };
    });
}

describe('preverFimDosSuprimentos', () => {
    it('consumo de 2 pontos por dia com 40% restantes acaba em ~20 dias', () => {
        const tinta = serie('Preto', 20, d => 40 + 2 * d);
        expect(preverFimDosSuprimentos(tinta, AGORA)).toEqual({ Preto: 20 });
    });

    it('usa só o trecho depois da última troca de cartucho', () => {
        // Antes da troca (há 10 dias) caía 5/dia; depois cai 1/dia a partir de 100
        const tinta = serie('Ciano', 30, d => (d > 10 ? 20 + 5 * (d - 10) : 100 - (10 - d)));
        expect(preverFimDosSuprimentos(tinta, AGORA)).toEqual({ Ciano: 90 });
    });

    it('não prevê com poucos dias de dados ou sem queda', () => {
        expect(preverFimDosSuprimentos(serie('Preto', 5, d => 50 + 3 * d), AGORA)).toEqual({});
        expect(preverFimDosSuprimentos(serie('Preto', 30, () => 80), AGORA)).toEqual({});
    });

    it('não prevê quando a última leitura é antiga (impressora sem resposta)', () => {
        const tinta = serie('Magenta', 30, d => 30 + d).map(t => ({ ...t, em: t.em - 10 * DIA }));
        expect(preverFimDosSuprimentos(tinta, AGORA)).toEqual({});
    });

    it('ignora previsões além de 1 ano (consumo quase zero)', () => {
        const tinta = serie('Amarelo', 60, d => 95 + Math.round(d / 20));
        expect(preverFimDosSuprimentos(tinta, AGORA)).toEqual({});
    });

    it('calcula cada cor separadamente', () => {
        const tinta = [...serie('Preto', 14, d => 30 + d), ...serie('Ciano', 14, () => 70)];
        expect(preverFimDosSuprimentos(tinta, AGORA)).toEqual({ Preto: 30 });
    });
});

describe('previsaoAindaValida', () => {
    const previsao = { Preto: 2, Ciano: 40 };
    const niveis = { Preto: 4, Ciano: 50 };

    it('mantém a previsão enquanto o nível ao vivo não subiu', () => {
        const ao_vivo = [{ nome: 'Preto', percentual: 3 }, { nome: 'Ciano', percentual: 50 }];
        expect(previsaoAindaValida(previsao, niveis, ao_vivo)).toEqual({ Preto: 2, Ciano: 40 });
    });

    it('descarta a cor cujo cartucho foi trocado depois da última coleta', () => {
        const ao_vivo = [{ nome: 'Preto', percentual: 100 }, { nome: 'Ciano', percentual: 49 }];
        expect(previsaoAindaValida(previsao, niveis, ao_vivo)).toEqual({ Ciano: 40 });
    });

    it('sem cores válidas devolve null', () => {
        expect(previsaoAindaValida(previsao, niveis, [{ nome: 'Preto', percentual: 98 }])).toBeNull();
        expect(previsaoAindaValida(previsao, niveis, [])).toBeNull();
    });
});
