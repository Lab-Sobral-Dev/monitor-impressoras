// tests/presenca.test.js
'use strict';

// Diagnóstico de quando o SNMP não responde: o aparelho está ligado na rede?
const net = require('net');
const { verificarPresencaNaRede, db, dbReady } = require('../server');

let servidor;
let portaAberta;
let portaFechada;

beforeAll(async () => {
    servidor = net.createServer(socket => socket.destroy());
    await new Promise(resolve => servidor.listen(0, '127.0.0.1', resolve));
    portaAberta = servidor.address().port;

    // Porta que existiu e foi fechada: o sistema operacional responde recusando (RST)
    const temporario = net.createServer();
    await new Promise(resolve => temporario.listen(0, '127.0.0.1', resolve));
    portaFechada = temporario.address().port;
    await new Promise(resolve => temporario.close(resolve));
});

afterAll(async () => {
    await new Promise(resolve => servidor.close(resolve));
    await dbReady;
    await new Promise(resolve => db.close(resolve));
});

describe('verificarPresencaNaRede', () => {
    it('aparelho com porta de impressão aberta está na rede', async () => {
        const r = await verificarPresencaNaRede('127.0.0.1', { portas: [portaAberta, portaFechada] });
        expect(r).toEqual({ na_rede: true, portas_abertas: [portaAberta] });
    });

    it('conexão recusada também indica aparelho ligado', async () => {
        const r = await verificarPresencaNaRede('127.0.0.1', { portas: [portaFechada] });
        expect(r).toEqual({ na_rede: true, portas_abertas: [] });
    });

    it('nada respondendo = fora da rede', async () => {
        // 192.0.2.0/24 (TEST-NET-1) é reservado para documentação: nunca responde
        const r = await verificarPresencaNaRede('192.0.2.1', { portas: [9100], timeout: 300 });
        expect(r).toEqual({ na_rede: false, portas_abertas: [] });
    });
});
