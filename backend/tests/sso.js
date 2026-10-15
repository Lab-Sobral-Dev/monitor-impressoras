'use strict';

// Auxiliares de teste: simulam o Gestão emitindo o token de acoplamento
// e entrando pelo /api/auth/sso — única porta de entrada do sistema.
const crypto  = require('crypto');
const request = require('supertest');

function assinarTokenAcoplamento(payload, secret = process.env.DOCKING_SECRET_MONITOR_IMPRESSORAS) {
    const b64 = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
    const header = b64({ alg: 'HS256', typ: 'JWT' });
    const body   = b64({ produto: 'monitor-impressoras', exp: Math.floor(Date.now() / 1000) + 60, ...payload });
    const sig    = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
    return `${header}.${body}.${sig}`;
}

// Entra via SSO e devolve a sessão gravada pela página ({ token, usuario, perfil, permissoes })
async function entrarViaSSO(app, sub = 'admin.teste') {
    const res = await request(app).get('/api/auth/sso').query({ token: assinarTokenAcoplamento({ sub }) });
    const m = /sessionStorage\.setItem\('ic_token', (.*)\);/.exec(res.text);
    if (res.status !== 200 || !m) throw new Error(`SSO falhou (${res.status}): ${res.text}`);
    return JSON.parse(JSON.parse(m[1]));
}

module.exports = { assinarTokenAcoplamento, entrarViaSSO };
