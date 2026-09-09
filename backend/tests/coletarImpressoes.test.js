'use strict';

const http = require('http');

const TOKEN = 'token-teste-coleta';
let pageLogLines = [];
let jobPagesLines = [];
let mockServer;
let mockPort;

function startMockPagelogApi() {
    return new Promise((resolve) => {
        mockServer = http.createServer((req, res) => {
            const enviar = (status, payload) => {
                const body = JSON.stringify(payload);
                res.writeHead(status, { 'Content-Type': 'application/json' });
                res.end(body);
            };
            if (req.headers['x-api-key'] !== TOKEN) return enviar(401, { erro: 'token inválido' });

            const url = new URL(req.url, 'http://localhost');
            const sinceLine = Number(url.searchParams.get('since_line') || '0');
            if (url.pathname === '/api/pagelog') {
                return enviar(200, { lines: pageLogLines.slice(sinceLine), total_lines: pageLogLines.length });
            }
            if (url.pathname === '/api/jobpages') {
                return enviar(200, { lines: jobPagesLines.slice(sinceLine), total_lines: jobPagesLines.length });
            }
            enviar(404, { erro: 'not found' });
        });
        mockServer.listen(0, '127.0.0.1', () => {
            mockPort = mockServer.address().port;
            resolve();
        });
    });
}

function runQuery(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
    });
}

function limparImpressoes() {
    return new Promise((resolve, reject) => {
        db.run('DELETE FROM impressoes', err => err ? reject(err) : resolve());
    });
}

function zerarCursor() {
    return new Promise((resolve, reject) => {
        db.run('UPDATE impressoes_cursor SET last_line = 0, last_line_jobpages = 0 WHERE id = 1',
            err => err ? reject(err) : resolve());
    });
}

let coletarImpressoes, db, dbReady;

beforeAll(async () => {
    await startMockPagelogApi();
    process.env.PAGELOG_API_URL = `http://127.0.0.1:${mockPort}`;
    process.env.PAGELOG_API_TOKEN = TOKEN;
    jest.resetModules();
    ({ coletarImpressoes, db, dbReady } = require('../server'));
    await dbReady;
});

beforeEach(async () => {
    pageLogLines = [];
    jobPagesLines = [];
    await limparImpressoes();
    await zerarCursor();
});

afterAll(() => new Promise((resolve) => {
    mockServer.close(() => db.close(resolve));
}));

describe('coletarImpressoes', () => {
    it('usa a contagem real do job_pages.log quando o page_log só traz "total" (fila raw)', async () => {
        pageLogLines = [
            '"PIXMA130|vsantos|1|[09/Sep/2026:14:41:43 +0000]|total|0|192.86.221.55|Página de teste"'
        ];
        jobPagesLines = [
            'PIXMA130|vsantos|1|[09/Sep/2026:14:41:43 +0000]|1|1||Página de teste'
        ];

        await coletarImpressoes();

        const rows = await runQuery('SELECT * FROM impressoes');
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
            impressora: 'PIXMA130',
            usuario: 'vsantos',
            job_id: 1,
            paginas: 1,
            copias: 1,
            hostname_origem: '192.86.221.55',
            documento: 'Página de teste'
        });
    });

    it('mantém pagina/copias do page_log quando não há job_pages.log correspondente', async () => {
        pageLogLines = [
            '"PIXMA130|jsilva|9|[09/Sep/2026:15:00:00 +0000]|3|2|LABTI07|relatorio.pdf"'
        ];
        jobPagesLines = [];

        await coletarImpressoes();

        const rows = await runQuery('SELECT * FROM impressoes');
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({ paginas: 3, copias: 2, hostname_origem: 'LABTI07' });
    });

    it('não sobrescreve com job_pages.log de outra impressora/job', async () => {
        pageLogLines = [
            '"PIXMA130|jsilva|9|[09/Sep/2026:15:00:00 +0000]|total|0|LABTI07|relatorio.pdf"'
        ];
        jobPagesLines = [
            'OUTRA|jsilva|9|[09/Sep/2026:15:00:00 +0000]|5|1||relatorio.pdf'
        ];

        await coletarImpressoes();

        const rows = await runQuery('SELECT * FROM impressoes');
        expect(rows).toHaveLength(1);
        expect(rows[0].paginas).toBeNull();
    });

    it('avança os dois cursores (page_log e job_pages.log) de forma independente', async () => {
        pageLogLines = ['"PIXMA130|jsilva|1|[09/Sep/2026:15:00:00 +0000]|total|0|LABTI07|doc.pdf"'];
        jobPagesLines = [];

        await coletarImpressoes();

        const cursor1 = await runQuery('SELECT * FROM impressoes_cursor WHERE id = 1');
        expect(cursor1[0].last_line).toBe(1);
        expect(cursor1[0].last_line_jobpages).toBe(0);

        jobPagesLines = ['PIXMA130|jsilva|1|[09/Sep/2026:15:00:00 +0000]|4|1||doc.pdf'];
        await coletarImpressoes();

        const cursor2 = await runQuery('SELECT * FROM impressoes_cursor WHERE id = 1');
        expect(cursor2[0].last_line).toBe(1);
        expect(cursor2[0].last_line_jobpages).toBe(1);
    });
});
