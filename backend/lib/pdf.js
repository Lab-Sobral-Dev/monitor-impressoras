'use strict';

// ── Gerador de PDF mínimo para impressão ─────────────────────────────────────
function gerarPDF(texto, relatorio = null) {
    const esc = s => String(s ?? '')
        .normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
        .replace(/[^\x20-\x7E]/g, ' ')
        .replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
    const num = n => Number(n || 0).toFixed(2).replace(/\.00$/, '');
    const rgb = {
        accent: [0.98, 0.40, 0.01], ink: [0.08, 0.10, 0.14], muted: [0.38, 0.41, 0.46],
        line: [0.86, 0.87, 0.89], ok: [0.06, 0.55, 0.34], warn: [0.88, 0.45, 0.03],
        bad: [0.75, 0.12, 0.12], cyan: [0.02, 0.62, 0.72], magenta: [0.75, 0.12, 0.55],
        yellow: [0.90, 0.66, 0.04], black: [0.08, 0.10, 0.14], def: [0.98, 0.40, 0.01],
        white: [1, 1, 1]
    };
    const c = arr => `${num(arr[0])} ${num(arr[1])} ${num(arr[2])}`;
    const corTinta = nome => {
        const n = String(nome || '').toLowerCase();
        if (n.includes('cyan') || n.includes('ciano')) return rgb.cyan;
        if (n.includes('magenta')) return rgb.magenta;
        if (n.includes('yellow') || n.includes('amarelo')) return rgb.yellow;
        if (n.includes('black') || n.includes('preto')) return rgb.black;
        return rgb.def;
    };
    const pages = [];
    let ops = [];
    let y = 800;
    const margin = 42, width = 595, height = 842, usable = width - margin * 2;
    const newPage = () => { if (ops.length) pages.push(ops.join('\n')); ops = []; y = 800; };
    const ensure = h => { if (y - h < 44) newPage(); };
    const rect = (x, ry, w, h, color) => ops.push(`q ${c(color)} rg ${num(x)} ${num(ry)} ${num(w)} ${num(h)} re f Q`);
    const textAt = (s, x, ty, size = 10, color = rgb.ink, font = 'F1') =>
        ops.push(`BT /${font} ${size} Tf ${c(color)} rg ${num(x)} ${num(ty)} Td (${esc(s)}) Tj ET`);
    const wrap = (s, max = 88) => {
        const words = esc(s).split(/\s+/).filter(Boolean);
        const lines = [];
        let cur = '';
        words.forEach(w => {
            if ((cur + ' ' + w).trim().length > max) { if (cur) lines.push(cur); cur = w; }
            else cur = (cur + ' ' + w).trim();
        });
        if (cur) lines.push(cur);
        return lines.length ? lines : [''];
    };
    const section = title => {
        ensure(38);
        y -= 16;
        rect(margin, y - 5, 5, 20, rgb.accent);
        textAt(title, margin + 12, y, 13, rgb.ink, 'F2');
        y -= 18;
        rect(margin, y, usable, 0.8, rgb.line);
        y -= 10;
    };
    const bodyLines = raw => {
        String(raw || '').split('\n').forEach(line => {
            const clean = line.replace(/\s*\|\s*/g, '   ');
            if (!clean.trim()) { y -= 6; return; }
            wrap(clean, 96).forEach(l => {
                ensure(14);
                textAt(l, margin, y, 9, rgb.ink);
                y -= 13;
            });
        });
    };
    const tintaBars = rows => {
        const latest = {};
        (Array.isArray(rows) ? rows : []).forEach(r => {
            const cor = r.cor || r.nome || 'Tinta';
            if (!latest[cor] || String(r.dia || '') >= String(latest[cor].dia || '')) latest[cor] = r;
        });
        Object.values(latest).forEach(r => {
            const pct = Math.max(0, Math.min(100, Number(r.percentual_medio ?? r.percentual ?? 0)));
            ensure(36);
            textAt(`${r.cor || r.nome || 'Tinta'} - ${pct}%`, margin, y, 10, pct <= 10 ? rgb.bad : pct <= 25 ? rgb.warn : rgb.ink, 'F2');
            y -= 14;
            rect(margin, y, usable, 10, rgb.line);
            rect(margin, y, usable * pct / 100, 10, corTinta(r.cor || r.nome));
            y -= 20;
        });
    };

    rect(0, 786, width, 56, rgb.accent);
    textAt(relatorio?.titulo || 'Relatorio de impressoras', margin, 812, 18, rgb.white, 'F2');
    textAt(`Gerado em ${new Date().toLocaleString('pt-BR')}`, margin, 794, 9, rgb.white);
    y = 760;
    if (relatorio && Array.isArray(relatorio.secoes)) {
        relatorio.secoes.forEach(secao => {
            section(secao.titulo || 'Secao');
            if (Array.isArray(secao.tinta) && secao.tinta.length) tintaBars(secao.tinta);
            bodyLines(secao.texto || '');
        });
    } else {
        section('Conteudo');
        bodyLines(texto);
    }
    newPage();

    const objects = ['1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'];
    const kids = pages.map((_, i) => `${3 + i * 2} 0 R`).join(' ');
    objects.push(`2 0 obj\n<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>\nendobj\n`);
    pages.forEach((stream, i) => {
        const pageObj = 3 + i * 2, contentObj = pageObj + 1;
        objects.push(`${pageObj} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${width} ${height}] /Contents ${contentObj} 0 R /Resources << /Font << /F1 ${3 + pages.length * 2} 0 R /F2 ${4 + pages.length * 2} 0 R >> >> >>\nendobj\n`);
        objects.push(`${contentObj} 0 obj\n<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}\nendstream\nendobj\n`);
    });
    const font1 = 3 + pages.length * 2, font2 = font1 + 1;
    objects.push(`${font1} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n`);
    objects.push(`${font2} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n`);
    const hdr = '%PDF-1.4\n';
    const offsets = [];
    let pos = Buffer.byteLength(hdr, 'latin1');
    objects.forEach(o => { offsets.push(pos); pos += Buffer.byteLength(o, 'latin1'); });
    const xrefPos = pos;
    const p = n => String(n).padStart(10, '0');
    const xref = 'xref\n0 ' + (objects.length + 1) + '\n0000000000 65535 f \r\n' +
        offsets.map(o => `${p(o)} 00000 n \r\n`).join('');
    const trailer = `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`;
    return Buffer.concat([hdr, ...objects, xref, trailer].map(s => Buffer.from(s, 'latin1')));
}

module.exports = { gerarPDF };
