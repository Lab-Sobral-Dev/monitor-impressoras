// tests/hp.test.js
'use strict';

// Leitura de níveis pela página interna da HP (/DevMgmt/ConsumableConfigDyn.xml),
// com trechos reais das LaserJet Pro 4103fdw do parque.
const { interpretarConsumiveisHP, interpretarSuprimentosHPWeb, db, dbReady } = require('../server');

afterAll(() => dbReady.then(() => new Promise(resolve => db.close(resolve))));

function consumivel({ tipo = 'toner', cor = 'K', percentual, recarregado = false, anterior = '' }) {
    return `<ccdyn:ConsumableInfo>
        <dd:ConsumableLabelCode>${cor}</dd:ConsumableLabelCode>
        <dd:ConsumableLifeState>
            <dd:ConsumableState>${recarregado ? 'refilledBlack' : 'veryLow'}</dd:ConsumableState>
            <dd:Brand>HP</dd:Brand>
            <dd:IsRefilled>${recarregado}</dd:IsRefilled>
        </dd:ConsumableLifeState>
        ${percentual === undefined ? '' : `<dd:ConsumablePercentageLevelRemaining>${percentual}</dd:ConsumablePercentageLevelRemaining>`}
        <dd:ConsumableTypeEnum>${tipo}</dd:ConsumableTypeEnum>
        ${anterior}
    </ccdyn:ConsumableInfo>`;
}

const xml = (...itens) => `<?xml version="1.0"?><ccdyn:ConsumableConfigDyn>
    <ccdyn:ProductConsumableInfo>
        <ccdyn:SupportedConsumables><ccdyn:SupportedConsumable>
            <dd:ConsumableTypeEnum>ink</dd:ConsumableTypeEnum><dd:ConsumableLabelCode>K</dd:ConsumableLabelCode>
        </ccdyn:SupportedConsumable></ccdyn:SupportedConsumables>
    </ccdyn:ProductConsumableInfo>
    ${itens.join('\n')}
</ccdyn:ConsumableConfigDyn>`;

describe('interpretarConsumiveisHP', () => {
    it('lê o percentual que o SNMP informa como desconhecido (Financeiro: toner em 0%)', () => {
        expect(interpretarConsumiveisHP(xml(consumivel({ percentual: 0 })))).toEqual({
            suprimentos: [{ nome: 'Preto', percentual: 0 }],
            recarregado: false
        });
    });

    it('cartucho recarregado: sem percentual, mas sinaliza o motivo (PCP/Compras)', () => {
        const anterior = `<ccdyn:PreviousCartridgeData>
            <dd:ConsumablePercentageLevelRemaining>100</dd:ConsumablePercentageLevelRemaining>
        </ccdyn:PreviousCartridgeData>`;
        expect(interpretarConsumiveisHP(xml(consumivel({ recarregado: true, anterior })))).toEqual({
            suprimentos: [],
            recarregado: true
        });
    });

    it('ignora dados do cartucho anterior', () => {
        const anterior = `<ccdyn:PreviousCartridgeData>
            <dd:ConsumablePercentageLevelRemaining>100</dd:ConsumablePercentageLevelRemaining>
        </ccdyn:PreviousCartridgeData>`;
        expect(interpretarConsumiveisHP(xml(consumivel({ percentual: 35, anterior }))).suprimentos)
            .toEqual([{ nome: 'Preto', percentual: 35 }]);
    });

    it('lê impressora colorida na ordem padrão e cartucho tricolor (CMY)', () => {
        const r = interpretarConsumiveisHP(xml(
            consumivel({ tipo: 'ink', cor: 'CMY', percentual: 40 }),
            consumivel({ tipo: 'ink', cor: 'K', percentual: 70 })
        ));
        expect(r.suprimentos).toEqual([
            { nome: 'Preto', percentual: 70 },
            { nome: 'Ciano', percentual: 40 },
            { nome: 'Magenta', percentual: 40 },
            { nome: 'Amarelo', percentual: 40 },
        ]);
    });

    it('ignora itens que não são tinta/toner e XML inválido', () => {
        expect(interpretarConsumiveisHP(xml(consumivel({ tipo: 'drum', percentual: 50 }))).suprimentos).toEqual([]);
        expect(interpretarConsumiveisHP('<html>erro</html>')).toEqual({ suprimentos: [], recarregado: false });
    });
});

// Trecho real da pagina de suprimentos da HP LaserJet E42540 (Logistica)
function paginaSuprimentos(blocos, garantiaEncerrada = true) {
    return `<h1>Supplies Status Page</h1><div class="page columns columns-1"><div class="content-columns">
        <div class="sections column column-1"><div class="content-columns">${blocos.join('')}</div>
        ${garantiaEncerrada ? '<p class="data data-empty"><span>§§ The HP warranty on this supply has ended.</span></p>' : ''}
        </div></div></div>`;
}

function blocoCartucho(cor, percentual, paginas) {
    const id = cor[0].toUpperCase() + cor.slice(1) + 'Cartridge1';
    return `<div class="section consumable-block consumable-block-${cor} toner toner-hp-unknow"><div class="section-content">
        <div class="consumable-block-header"><h2 id="${id}-Header">${cor} Cartridge</h2>
        <p class="data percentage">${percentual}</p><p class="data"><span>Order W9024MC</span></p>
        <div class="color"><div class="color-size 0" style="width:2%"><strong id="${id}-Header_Level">2%</strong></div></div></div>
        <p class="data"><span>Status:</span><strong id="${id}-SupplyState">OK</strong></p>
        <p class="data"><span>Pages printed with this supply:*</span><strong id="${id}-PagesPrintedWithSupply">${paginas}</strong></p>
        </div></div>`;
}

describe('interpretarSuprimentosHPWeb', () => {
    it('nivel "--%" = desconhecido, com paginas impressas e garantia encerrada (Logistica)', () => {
        const html = paginaSuprimentos([blocoCartucho('black', '--%*', '40868')]);
        expect(interpretarSuprimentosHPWeb(html)).toEqual([
            { nome: 'Preto', percentual: null, paginas: 40868, garantiaEncerrada: true }
        ]);
    });

    it('le percentual real quando a HP informa (nao confunde com a barra de 2%)', () => {
        const html = paginaSuprimentos([blocoCartucho('black', '35%*', '1200'), blocoCartucho('cyan', '80%*', '900')], false);
        expect(interpretarSuprimentosHPWeb(html)).toEqual([
            { nome: 'Preto', percentual: 35, paginas: 1200, garantiaEncerrada: false },
            { nome: 'Ciano', percentual: 80, paginas: 900, garantiaEncerrada: false }
        ]);
    });

    it('pagina diferente ou vazia nao gera itens', () => {
        expect(interpretarSuprimentosHPWeb('<html>Login</html>')).toEqual([]);
    });
});
