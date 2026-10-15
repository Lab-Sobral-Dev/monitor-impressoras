'use strict';

// Análises sobre o histórico de leituras (funções puras, sem banco):
// leitura de nível parada, previsão de fim da tinta/toner, consumo diário e
// horas do expediente.

const DIA_MS = 24 * 60 * 60 * 1000;
const LEITURA_PARADA_DIAS    = 14;
const LEITURA_PARADA_PAGINAS = 500;
const SALTO_MAXIMO_CONTADOR  = 50000; // salto maior = contador de outro aparelho (troca no mesmo IP)
const PREVISAO_JANELA_DIAS   = 90;
const PREVISAO_MIN_DIAS      = 7;
const PREVISAO_MIN_QUEDA     = 3;   // pontos percentuais
const PREVISAO_SUBIDA_TROCA  = 5;   // subida maior que isso = cartucho trocado/recarregado
const PREVISAO_MAX_DIAS      = 365;

// Leitura não confiável: nenhuma cor muda há LEITURA_PARADA_DIAS e a impressora
// imprimiu ao menos LEITURA_PARADA_PAGINAS no período — o nível exibido
// provavelmente não é real (tinta compatível/a granel, chip que não informa consumo).
// tinta: [{ cor, percentual, em }], paginas: [{ total, em }] — `em` em milissegundos
function detectarLeituraParada(tinta, paginas, agora = Date.now()) {
    if (!tinta.length) return null;
    const ordenadas = [...tinta].sort((a, b) => a.em - b.em);
    const ultimaColeta = ordenadas[ordenadas.length - 1].em;
    const atual = new Map(ordenadas.filter(t => t.em === ultimaColeta).map(t => [t.cor, t.percentual]));

    // O trecho parado começa na mudança mais recente entre todas as cores
    let desde = ordenadas[0].em;
    for (const t of ordenadas) {
        if (atual.has(t.cor) && t.percentual !== atual.get(t.cor) && t.em > desde) desde = t.em;
    }

    let impressas = 0;
    const contadores = paginas.filter(p => p.em >= desde && p.total !== null).sort((a, b) => a.em - b.em);
    for (let i = 1; i < contadores.length; i++) {
        const delta = contadores[i].total - contadores[i - 1].total;
        if (delta > 0 && delta <= SALTO_MAXIMO_CONTADOR) impressas += delta;
    }

    const dias = Math.floor((agora - desde) / DIA_MS);
    if (dias < LEITURA_PARADA_DIAS || impressas < LEITURA_PARADA_PAGINAS) return null;
    return { desde: new Date(desde).toISOString(), dias, paginas: impressas, niveis: Object.fromEntries(atual) };
}

// Previsão: consumo médio desde a última troca/recarga (nível subiu), por
// regressão linear do percentual no tempo.
// tinta: [{ cor, percentual, em (ms) }] → { Preto: 12, ... } (só cores com previsão confiável)
function preverFimDosSuprimentos(tinta, agora = Date.now()) {
    const previsao = {};
    const inicioJanela = agora - PREVISAO_JANELA_DIAS * DIA_MS;
    const porCor = new Map();
    for (const t of tinta) {
        if (t.em < inicioJanela || typeof t.percentual !== 'number') continue;
        if (!porCor.has(t.cor)) porCor.set(t.cor, []);
        porCor.get(t.cor).push(t);
    }
    for (const [cor, leituras] of porCor) {
        leituras.sort((a, b) => a.em - b.em);
        let inicio = 0;
        for (let i = 1; i < leituras.length; i++) {
            if (leituras[i].percentual > leituras[i - 1].percentual + PREVISAO_SUBIDA_TROCA) inicio = i;
        }
        const trecho = leituras.slice(inicio);
        if (trecho.length < 2) continue;
        const primeira = trecho[0];
        const ultima = trecho[trecho.length - 1];
        if (agora - ultima.em > 3 * DIA_MS) continue; // sem leitura recente, a previsão estaria velha
        if ((ultima.em - primeira.em) / DIA_MS < PREVISAO_MIN_DIAS) continue;
        if (primeira.percentual - ultima.percentual < PREVISAO_MIN_QUEDA || ultima.percentual <= 0) continue;

        // Inclinação (pontos percentuais por dia) por mínimos quadrados
        const n = trecho.length;
        const xs = trecho.map(t => (t.em - primeira.em) / DIA_MS);
        const ys = trecho.map(t => t.percentual);
        const mx = xs.reduce((a, b) => a + b, 0) / n;
        const my = ys.reduce((a, b) => a + b, 0) / n;
        let num = 0, den = 0;
        for (let i = 0; i < n; i++) { num += (xs[i] - mx) * (ys[i] - my); den += (xs[i] - mx) ** 2; }
        const inclinacao = den ? num / den : 0;
        if (inclinacao >= 0) continue;

        const dias = Math.round(ultima.percentual / -inclinacao);
        if (dias <= PREVISAO_MAX_DIAS) previsao[cor] = dias;
    }
    return previsao;
}

// Estoque × consumo: para cada item do estoque, soma o consumo (pontos
// percentuais por dia) das impressoras abastecidas por aquele grupo — antes
// somava qualquer impressora da mesma cor, de qualquer modelo. Uma unidade em
// estoque = 100% de um cartucho/garrafa.
function consumoDiarioPorImpressora(historico) {
    const series = new Map();
    for (const h of historico) {
        const chave = `${h.impressora_id}|${h.cor}`;
        if (!series.has(chave)) series.set(chave, []);
        series.get(chave).push({ percentual: h.percentual, em: Date.parse(h.coletado_em) });
    }
    const consumo = new Map();
    for (const [chave, leituras] of series) {
        leituras.sort((a, b) => a.em - b.em);
        const dias = (leituras[leituras.length - 1].em - leituras[0].em) / DIA_MS;
        if (dias < 1) continue;
        let quedas = 0;
        for (let i = 1; i < leituras.length; i++) quedas += Math.max(0, leituras[i - 1].percentual - leituras[i].percentual);
        consumo.set(chave, quedas / dias);
    }
    return consumo;
}

// Chave do período no horário local: hora "2026-10-15T14:00", dia "2026-10-15",
// mês "2026-10", ano "2026"
const TAMANHO_CHAVE = { dia: 10, mes: 7, ano: 4 };

function chavePeriodo(ms, periodo, fusoHoras) {
    const local = new Date(ms + fusoHoras * 60 * 60 * 1000).toISOString();
    return periodo === 'hora' ? `${local.slice(0, 13)}:00` : local.slice(0, TAMANHO_CHAVE[periodo] ?? 10);
}

// Páginas impressas por período a partir das leituras do contador total.
// Soma a diferença entre leituras consecutivas e atribui ao período da leitura
// mais recente. (O cálculo antigo — maior menos menor dentro de cada período —
// perdia as páginas entre um período e o seguinte e zerava a visão por hora,
// já que a coleta é horária.) Saltos negativos ou enormes = contador de outro
// aparelho (troca no mesmo IP) e são ignorados.
// Diferenças entre leituras muito distantes (servidor ou impressora fora por
// dias) cairiam inteiras num único período; acima desse intervalo são ignoradas.
// 4 dias cobre noites e fins de semana.
const LACUNA_MAXIMA_DIAS = { hora: 4, dia: 4, mes: 31, ano: 366 };

// leituras: [{ total, em (ms) }]; desde: só conta leituras a partir desse instante
function paginasPorPeriodo(leituras, periodo, fusoHoras = 0, desde = 0) {
    const ordenadas = leituras.filter(l => l.total !== null && l.total !== undefined).sort((a, b) => a.em - b.em);
    const lacunaMaxima = (LACUNA_MAXIMA_DIAS[periodo] ?? 4) * DIA_MS;
    const soma = new Map();
    for (let i = 1; i < ordenadas.length; i++) {
        const atual = ordenadas[i];
        const anterior = ordenadas[i - 1];
        if (atual.em < desde || atual.em - anterior.em > lacunaMaxima) continue;
        const delta = atual.total - anterior.total;
        if (delta <= 0 || delta > SALTO_MAXIMO_CONTADOR) continue;
        const chave = chavePeriodo(atual.em, periodo, fusoHoras);
        soma.set(chave, (soma.get(chave) || 0) + delta);
    }
    return [...soma].sort(([a], [b]) => a.localeCompare(b)).map(([p, paginas]) => ({ periodo: p, paginas_impressas: paginas }));
}

// Faixas "08-12,14-17" → horas cheias do expediente [8, 9, 10, 11, 14, 15, 16]
function horasDoExpediente(texto) {
    const horas = new Set();
    for (const faixa of String(texto || '').split(',')) {
        const m = /^\s*(\d{1,2})\s*-\s*(\d{1,2})\s*$/.exec(faixa);
        if (!m) continue;
        for (let h = Number(m[1]); h < Number(m[2]) && h < 24; h++) horas.add(h);
    }
    return [...horas].sort((a, b) => a - b);
}

module.exports = {
    DIA_MS,
    detectarLeituraParada,
    preverFimDosSuprimentos,
    consumoDiarioPorImpressora,
    paginasPorPeriodo,
    chavePeriodo,
    horasDoExpediente
};
