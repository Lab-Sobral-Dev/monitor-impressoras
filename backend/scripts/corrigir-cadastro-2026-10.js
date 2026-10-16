// Correção pontual do cadastro de impressoras — levantamento de 15/10/2026.
//
// O que faz (identificando cada impressora pelo IP):
//   1. .92  Físico-químico : Canon GX6000 → Epson WF-C5810 (aparelho trocado no mesmo IP)
//   2. .20  Contabilidade  : Kyocera M2040dn → Samsung SL-M4070FR (aparelho trocado no mesmo IP)
//   3. .210 Qualidade      : cadastra a HP Color LaserJet Flow E57540 (impressora nova)
//   4. .156 Microbiológico : HP 4103fdw passa a ser conexão USB (sem IP, sem monitoramento)
//   5. Padroniza os nomes de localização (espaço sobrando, acentos, maiúsculas), para que
//      o mesmo setor não apareça duas vezes nos filtros e agrupamentos
//   6. Apaga do estoque o grupo antigo "Canon GX7010" — as Canon GX usam o grupo
//      "Canon GX6010 / GX7010"; o antigo não aparecia em tela nenhuma (decisão de 15/10/2026)
//   7. Histórico de status: coletas gravadas como "offline" em que o contador de páginas
//      foi lido viram "online" — o bug antigo das monocromáticas (HPs, Kyocera) gravava
//      offline com a impressora respondendo, e a disponibilidade delas aparecia ~6%
//   8. Histórico de tinta: apaga as "cores" das impressoras monocromáticas (eram fusor e
//      rolos da Samsung lidos como Ciano/Magenta/Amarelo pelo bug antigo)
//
// Rodar DEPOIS de subir a versão com nº de série e conexão USB (o servidor cria
// as colunas numero_serie e conexao ao iniciar).
//
// Uso (dentro do container):
//   docker compose exec app node scripts/corrigir-cadastro-2026-10.js            → só mostra o que mudaria
//   docker compose exec app node scripts/corrigir-cadastro-2026-10.js --aplicar  → aplica
//
// Pode ser rodado mais de uma vez: o que já estiver correto é ignorado.
'use strict';

const sqlite3 = require('sqlite3');

const DB_PATH = process.env.DATABASE_PATH || './banco.db';
const APLICAR = process.argv.includes('--aplicar');

const ATUALIZACOES = [
    {
        descricao: '.92 Físico-químico → Epson WF-C5810',
        ip: '192.86.221.92',
        campos: { nome: 'Epson', modelo: 'EPSON WF-C5810 Series', tipo: 'Colorido', material: 'Tinta', numero_serie: 'XBJX038395' }
    },
    {
        descricao: '.20 Contabilidade → Samsung SL-M4070FR',
        ip: '192.86.221.20',
        campos: { nome: 'Samsung', modelo: 'Samsung SL-M4070FR', tipo: 'Mono', material: 'Toner', numero_serie: 'ZDDPB07K913WRZY' }
    },
    {
        descricao: '.156 Microbiológico → conexão USB',
        ip: '192.86.221.156',
        campos: { conexao: 'usb', ip: null }
    }
];

// Nome atual exato → nome padronizado
const LOCALIZACOES = [
    { de: 'Contabilidade ',        para: 'Contabilidade' },
    { de: 'Fisico-quimico',        para: 'Físico-químico' },
    { de: 'LOGISTICA',             para: 'Logística' },
    { de: 'Produção ',             para: 'Produção' },
    { de: 'Sistema de qualidade ', para: 'Sistema de qualidade' },
];

// Grupos do estoque que não são mais usados por nenhuma impressora
const GRUPOS_ESTOQUE_REMOVIDOS = ['Canon GX7010'];

const INCLUSOES = [
    {
        descricao: '.210 Qualidade → nova HP Color LaserJet Flow E57540',
        campos: {
            nome: 'HP', ip: '192.86.221.210', modelo: 'HP Color LaserJet Flow E57540', localizacao: 'Sistema de qualidade',
            comunidade: 'public', tipo: 'Colorido', material: 'Toner', numero_serie: 'BRBSP970FP', conexao: 'rede'
        }
    }
];

const db = new sqlite3.Database(DB_PATH, sqlite3.OPEN_READWRITE);
const all = (sql, p = []) => new Promise((ok, erro) => db.all(sql, p, (e, r) => e ? erro(e) : ok(r)));
const get = (sql, p = []) => new Promise((ok, erro) => db.get(sql, p, (e, r) => e ? erro(e) : ok(r)));
const run = (sql, p = []) => new Promise((ok, erro) => db.run(sql, p, function (e) { e ? erro(e) : ok(this); }));

function resumo(imp) {
    return `#${imp.id} ${imp.nome} | ${imp.modelo} | ${imp.ip ?? 'sem IP'} | ${imp.localizacao} | série ${imp.numero_serie ?? '-'} | ${imp.conexao}`;
}

async function main() {
    console.log(`Banco: ${DB_PATH}`);
    console.log(APLICAR ? 'Modo: APLICAR\n' : 'Modo: simulação (nada é gravado — use --aplicar para gravar)\n');

    const colunas = (await all('PRAGMA table_info(impressoras)')).map(c => c.name);
    const faltando = ['numero_serie', 'conexao'].filter(c => !colunas.includes(c));
    if (faltando.length) {
        throw new Error(`colunas ausentes (${faltando.join(', ')}). Suba a versão nova do sistema antes de rodar este script.`);
    }

    let alteradas = 0;
    await run('BEGIN');
    try {
        for (const a of ATUALIZACOES) {
            const imp = await get('SELECT * FROM impressoras WHERE ip = ?', [a.ip]);
            if (!imp) {
                // Pode já ter sido aplicado (ex.: USB deixa o IP vazio)
                console.log(`· ${a.descricao}: nenhuma impressora com IP ${a.ip} — já aplicado ou IP diferente, nada feito`);
                continue;
            }
            const mudancas = Object.entries(a.campos).filter(([k, v]) => imp[k] !== v);
            if (!mudancas.length) { console.log(`· ${a.descricao}: já está correto`); continue; }
            console.log(`→ ${a.descricao}\n    antes:  ${resumo(imp)}\n    depois: ${resumo({ ...imp, ...a.campos })}`);
            alteradas++;
            await run(`UPDATE impressoras SET ${mudancas.map(([k]) => `${k} = ?`).join(', ')} WHERE id = ?`,
                [...mudancas.map(([, v]) => v), imp.id]);
        }

        for (const l of LOCALIZACOES) {
            const afetadas = await all('SELECT id, ip FROM impressoras WHERE localizacao = ?', [l.de]);
            if (!afetadas.length) { console.log(`· Localização "${l.de}": nenhuma impressora — já padronizada`); continue; }
            console.log(`→ Localização "${l.de}" → "${l.para}" (${afetadas.map(a => `#${a.id} ${a.ip ?? 'USB'}`).join(', ')})`);
            alteradas += afetadas.length;
            await run('UPDATE impressoras SET localizacao = ? WHERE localizacao = ?', [l.para, l.de]);
        }

        for (const n of INCLUSOES) {
            const existente = await get('SELECT * FROM impressoras WHERE ip = ?', [n.campos.ip]);
            if (existente) { console.log(`· ${n.descricao}: já cadastrada (${resumo(existente)})`); continue; }
            console.log(`→ ${n.descricao}\n    nova:   ${resumo({ id: 'novo', ...n.campos })}`);
            alteradas++;
            const cols = Object.keys(n.campos);
            await run(`INSERT INTO impressoras (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`, Object.values(n.campos));
        }

        for (const grupo of GRUPOS_ESTOQUE_REMOVIDOS) {
            const itens = await all('SELECT insumo, quantidade, estado FROM estoque WHERE modelo = ?', [grupo]);
            if (!itens.length) { console.log(`· Estoque "${grupo}": já removido`); continue; }
            console.log(`→ Estoque "${grupo}": apagar ${itens.map(i => `${i.insumo} ${i.quantidade}${i.estado && i.estado !== 'Novo' ? ` (${i.estado})` : ''}`).join(', ')}`);
            alteradas += itens.length;
            await run('DELETE FROM estoque WHERE modelo = ?', [grupo]);
        }

        // 7. Status: contador de páginas lido na mesma coleta = impressora respondendo
        const statusErrado = await all(
            `SELECT i.localizacao, i.ip, COUNT(*) AS n FROM historico_status s JOIN impressoras i ON i.id = s.impressora_id
             WHERE s.online = 0 AND EXISTS (SELECT 1 FROM historico_paginas p
                   WHERE p.impressora_id = s.impressora_id AND p.coletado_em = s.registrado_em)
             GROUP BY s.impressora_id ORDER BY n DESC`);
        if (!statusErrado.length) console.log('· Histórico de status: nada a corrigir');
        else {
            console.log(`→ Histórico de status: ${statusErrado.reduce((a, r) => a + r.n, 0)} coletas "offline" com contador lido viram "online" ` +
                `(${statusErrado.map(r => `${r.localizacao} ${r.n}`).join(', ')})`);
            alteradas += statusErrado.reduce((a, r) => a + r.n, 0);
            await run(`UPDATE historico_status SET online = 1 WHERE online = 0 AND EXISTS (SELECT 1 FROM historico_paginas p
                       WHERE p.impressora_id = historico_status.impressora_id AND p.coletado_em = historico_status.registrado_em)`);
        }

        // 8. Tinta: monocromática só tem Preto (o resto era fusor/rolos lidos como cor)
        const coresFalsas = await all(
            `SELECT i.localizacao, i.ip, COUNT(*) AS n FROM historico_tinta h JOIN impressoras i ON i.id = h.impressora_id
             WHERE i.tipo = 'Mono' AND h.cor <> 'Preto' GROUP BY h.impressora_id`);
        if (!coresFalsas.length) console.log('· Histórico de tinta: nenhuma cor falsa em monocromática');
        else {
            console.log(`→ Histórico de tinta: apagar ${coresFalsas.reduce((a, r) => a + r.n, 0)} leituras de "cor" em monocromáticas ` +
                `(${coresFalsas.map(r => `${r.localizacao} ${r.ip} ${r.n}`).join(', ')})`);
            alteradas += coresFalsas.reduce((a, r) => a + r.n, 0);
            await run(`DELETE FROM historico_tinta WHERE cor <> 'Preto'
                       AND impressora_id IN (SELECT id FROM impressoras WHERE tipo = 'Mono')`);
        }

        await run(APLICAR ? 'COMMIT' : 'ROLLBACK');
        if (!alteradas) console.log('\nNada a alterar — o cadastro já está correto.');
        else if (APLICAR) console.log(`\n${alteradas} alteração(ões) gravada(s). O painel reflete em até 1 minuto.`);
        else console.log(`\nSimulação: ${alteradas} alteração(ões) seriam feitas — nada foi gravado.`);
    } catch (e) {
        await run('ROLLBACK');
        throw e;
    }
}

main()
    .catch(e => { console.error(`\nErro: ${e.message}`); process.exitCode = 1; })
    .finally(() => db.close());
