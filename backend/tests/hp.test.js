// tests/hp.test.js
'use strict';

// Leitura de níveis pela página interna da HP (/DevMgmt/ConsumableConfigDyn.xml),
// com trechos reais das LaserJet Pro 4103fdw do parque.
const { interpretarConsumiveisHP, db, dbReady } = require('../server');

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
