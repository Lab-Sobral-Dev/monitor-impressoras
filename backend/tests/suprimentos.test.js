// tests/suprimentos.test.js
'use strict';

// Casos montados com o que as impressoras reais do parque respondem via SNMP
// (tabela prtMarkerSupplies: tipo, índice do corante, descrição, máximo, nível).
const { interpretarSuprimentos, serieDivergente, db, dbReady } = require('../server');

afterAll(() => dbReady.then(() => new Promise(resolve => db.close(resolve))));

const CORANTES_PADRAO = { 1: 'black', 2: 'cyan', 3: 'magenta', 4: 'yellow' };

describe('interpretarSuprimentos', () => {
    it('lê as 4 cores e ignora a caixa de manutenção (Canon GX)', () => {
        const itens = [
            { tipo: 6, corante: 1, descricao: 'Canon Black Ink Tank',   max: 100, nivel: 83 },
            { tipo: 6, corante: 2, descricao: 'Canon Cyan Ink Tank',    max: 100, nivel: 74 },
            { tipo: 6, corante: 3, descricao: 'Canon Magenta Ink Tank', max: 100, nivel: 99 },
            { tipo: 6, corante: 4, descricao: 'Canon Yellow Ink Tank',  max: 100, nivel: 98 },
            { tipo: 8, corante: 0, descricao: 'Maintenance Cartridge',  max: 100, nivel: 24 },
        ];
        expect(interpretarSuprimentos(itens, CORANTES_PADRAO)).toEqual([
            { nome: 'Preto', percentual: 83 },
            { nome: 'Ciano', percentual: 74 },
            { nome: 'Magenta', percentual: 99 },
            { nome: 'Amarelo', percentual: 98 },
        ]);
    });

    it('monocromática: só o preto, sem inventar cores a partir de fusor e rolos (Samsung)', () => {
        const itens = [
            { tipo: 3,  corante: 1, descricao: 'Black Toner Cartridge', max: 15000,  nivel: 14550 },
            { tipo: 15, corante: 0, descricao: 'Fuser',                 max: 90000,  nivel: 89556 },
            { tipo: 1,  corante: 0, descricao: 'Transfer Roller',       max: 100000, nivel: 99556 },
            { tipo: 1,  corante: 0, descricao: 'MP Roller',             max: 100000, nivel: 99477 },
        ];
        expect(interpretarSuprimentos(itens, { 1: 'Black' })).toEqual([{ nome: 'Preto', percentual: 97 }]);
    });

    it('ignora a caixa de resíduo de toner (Kyocera)', () => {
        const itens = [
            { tipo: 3, corante: 1, descricao: 'TK-1175',         max: 12000, nivel: 10200 },
            { tipo: 4, corante: 0, descricao: 'Waste Toner Box', max: -2,    nivel: -3 },
        ];
        expect(interpretarSuprimentos(itens, { 1: 'black' })).toEqual([{ nome: 'Preto', percentual: 85 }]);
    });

    it('usa a cor informada pela impressora, não a posição na tabela (Brother: preto, amarelo, ciano, magenta)', () => {
        const itens = [
            { tipo: 6, corante: 4, descricao: 'Black Ink Cartridge',   max: 100, nivel: 90 },
            { tipo: 6, corante: 3, descricao: 'Yellow Ink Cartridge',  max: 100, nivel: 10 },
            { tipo: 6, corante: 2, descricao: 'Cyan Ink Cartridge',    max: 100, nivel: 20 },
            { tipo: 6, corante: 1, descricao: 'Magenta Ink Cartridge', max: 100, nivel: 30 },
        ];
        const corantes = { 1: 'magenta', 2: 'cyan', 3: 'yellow', 4: 'black' };
        expect(interpretarSuprimentos(itens, corantes)).toEqual([
            { nome: 'Preto', percentual: 90 },
            { nome: 'Ciano', percentual: 20 },
            { nome: 'Magenta', percentual: 30 },
            { nome: 'Amarelo', percentual: 10 },
        ]);
    });

    it('nível desconhecido (-2) ou "há algum restante" (-3) não vira percentual (HP 4103)', () => {
        const itens = [{ tipo: 3, corante: 1, descricao: 'Black Cartridge HP W1030XC', max: 100, nivel: -2 }];
        expect(interpretarSuprimentos(itens, { 1: 'Black Cartridge' })).toEqual([]);
        expect(interpretarSuprimentos([{ ...itens[0], nivel: -3 }], { 1: 'Black Cartridge' })).toEqual([]);
    });

    it('identifica a cor pela descrição quando não há tabela de corantes', () => {
        const itens = [{ tipo: 21, corante: 0, descricao: 'Cartucho preto HP W9024MC black', max: 100, nivel: 50 }];
        expect(interpretarSuprimentos(itens, {})).toEqual([{ nome: 'Preto', percentual: 50 }]);
    });

    it('máximo -2 com nível em escala 0-255 é convertido para percentual', () => {
        const itens = [{ tipo: 5, corante: 1, descricao: 'Black', max: -2, nivel: 255 }];
        expect(interpretarSuprimentos(itens, CORANTES_PADRAO)).toEqual([{ nome: 'Preto', percentual: 100 }]);
    });
});

describe('serieDivergente', () => {
    it('acusa aparelho trocado quando as séries diferem', () => {
        expect(serieDivergente('KNDX03073', 'XBJX038395')).toBe(true);
    });

    it('ignora diferença de maiúsculas e espaços', () => {
        expect(serieDivergente(' kndx03073 ', 'KNDX03073')).toBe(false);
    });

    it('não acusa nada sem série cadastrada ou sem série lida', () => {
        expect(serieDivergente(null, 'KNDX03073')).toBe(false);
        expect(serieDivergente('KNDX03073', null)).toBe(false);
        expect(serieDivergente('', '')).toBe(false);
    });
});
