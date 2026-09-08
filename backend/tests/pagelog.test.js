// tests/pagelog.test.js
'use strict';

const { parsePageLogLine, db } = require('../server');

afterAll(() => new Promise(resolve => db.close(resolve)));

describe('parsePageLogLine', () => {
    it('faz parse de uma linha válida do page_log', () => {
        const linha = 'PIXMA130|jsilva|42|[08/Sep/2026:14:55:09 +0000]|1|1|LABTI07|relatorio.pdf';
        const r = parsePageLogLine(linha);
        expect(r).toEqual({
            impressora: 'PIXMA130',
            usuario: 'jsilva',
            jobId: 42,
            pagina: 1,
            copias: 1,
            hostname: 'LABTI07',
            documento: 'relatorio.pdf'
        });
    });

    it('retorna null para linha com menos de 8 campos', () => {
        expect(parsePageLogLine('PIXMA130|jsilva|42')).toBeNull();
    });

    it('retorna null quando impressora ou usuário estão vazios', () => {
        const linha = '|jsilva|42|[08/Sep/2026:14:55:09 +0000]|1|1|LABTI07|relatorio.pdf';
        expect(parsePageLogLine(linha)).toBeNull();
    });

    it('usa null pra campos numéricos não parseáveis', () => {
        const linha = 'PIXMA130|jsilva|abc|[08/Sep/2026:14:55:09 +0000]|x|y|LABTI07|relatorio.pdf';
        const r = parsePageLogLine(linha);
        expect(r.jobId).toBeNull();
        expect(r.pagina).toBeNull();
        expect(r.copias).toBeNull();
    });
});
