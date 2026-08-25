# Monitor de Impressoras

Sistema web para cadastro, monitoramento e administracao de impressoras em rede. A aplicacao acompanha status online/offline, niveis de tinta ou toner via SNMP, estoque de suprimentos, usuarios, permissoes e relatorios operacionais.

## Funcionalidades

- Dashboard com indicadores de total de impressoras, online, offline e suprimentos em alerta.
- Cadastro de impressoras com fabricante, modelo/setor, IP, localizacao, comunidade SNMP, tipo e material do suprimento.
- Monitoramento de niveis de tinta/toner por impressora.
- Controle de estoque de suprimentos.
- Gerenciamento de usuarios e permissoes.
- Autenticacao por usuario e senha.
- Suporte a WebAuthn/passkey e integracao Control iD quando configurados.
- Relatorios de ficha tecnica, paginas impressas, consumo de tinta, trocas de toner, disponibilidade e estoque versus consumo.
- Envio de impressao para impressoras de rede via IPP/RAW.
- Descoberta de impressora por IP.

## Estrutura do Projeto

```text
monitor-impressoras/
  backend/
    server.js          # API Express, banco SQLite, SNMP, autenticacao e relatorios
    package.json       # Dependencias e scripts Node.js
    banco.db           # Banco SQLite local
    .env.example       # Exemplo de variaveis de ambiente
    Dockerfile         # Imagem Docker da aplicacao
  frontend/
    public/            # Telas HTML, CSS e JS estaticos
  docs/                # Documentacao e materiais gerados
  docker-compose.yml   # Execucao via Docker Compose
  run-local-server.cmd # Script Windows para iniciar localmente
```

## Requisitos

- Node.js 20 ou superior.
- npm.
- Docker e Docker Compose, opcional para execucao em container.
- Impressoras de rede com SNMP habilitado para leitura automatica de status e suprimentos.

## Configuracao

Copie o arquivo de exemplo de ambiente:

```bash
cp backend/.env.example backend/.env
```

No Windows PowerShell:

```powershell
Copy-Item backend\.env.example backend\.env
```

Edite `backend/.env` conforme o ambiente:

```env
PORT=3000
DATABASE_PATH=./banco.db
SNMP_CONCURRENCY=5

ADMIN_USER=admin
ADMIN_SENHA=troque-esta-senha
ESTOQUE_SENHA=troque-este-token

WEBAUTHN_ORIGIN=http://localhost:3000
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=Monitor de Impressoras

ALLOWED_ORIGIN=http://localhost:3000
```

Importante: troque `ADMIN_SENHA` e `ESTOQUE_SENHA` antes de usar o sistema em producao.

## Execucao Local

Instale as dependencias:

```bash
cd backend
npm install
```

Inicie o servidor:

```bash
npm start
```

Acesse no navegador:

```text
http://localhost:3000
```

Credenciais padrao, caso mantidas no `.env` local:

```text
Usuario: admin
Senha: troque-esta-senha
```

## Execucao no Windows pelo Script

Na raiz do projeto, execute:

```bat
run-local-server.cmd
```

O script inicia o backend na porta `3000` e grava logs em `logs/`.

## Execucao com Docker

Crie ou ajuste `backend/.env` e execute:

```bash
docker compose up -d --build
```

Acesse:

```text
http://localhost:3000
```

O banco SQLite fica persistido no volume Docker `db_data`, mapeado internamente para `/data/banco.db`.

Para parar:

```bash
docker compose down
```

## Testes

Execute os testes do backend:

```bash
cd backend
npm test
```

## Principais Telas

- `login.html`: acesso ao sistema.
- `admin.html`: dashboard administrativo.
- `dispositivos.html`: lista e manutencao das impressoras.
- `cadastrar.html`: cadastro de novos equipamentos.
- `tinta.html`: acompanhamento dos niveis de tinta/toner.
- `estoque.html`: controle de suprimentos.
- `usuarios.html`: gerenciamento de usuarios.
- `relatorios.html`: relatorios tecnicos e operacionais.

## Principais Rotas da API

- `GET /api/dashboard`: dados do painel principal.
- `GET /api/impressoras`: lista impressoras cadastradas.
- `POST /api/impressoras`: cadastra impressora.
- `PUT /api/impressoras/:id`: atualiza impressora.
- `DELETE /api/impressoras/:id`: remove impressora.
- `GET /api/estoque`: consulta estoque.
- `POST /api/estoque`: atualiza estoque.
- `POST /api/auth/login`: autentica usuario.
- `GET /api/auth/verify`: valida sessao autenticada.
- `GET /api/usuarios`: lista usuarios.
- `POST /api/usuarios`: cria usuario.
- `PUT /api/usuarios/:id`: atualiza usuario.
- `GET /api/descobrir?ip=...`: descobre informacoes de impressora por IP.
- `GET /api/relatorios/impressoras`: relatorio de ficha tecnica.
- `GET /api/relatorios/paginas/:id`: relatorio de paginas impressas.
- `GET /api/relatorios/tinta/:id`: historico de tinta.
- `GET /api/relatorios/disponibilidade`: disponibilidade das impressoras.
- `GET /api/relatorios/estoque`: estoque versus consumo.

## Observacoes de Producao

- Use senhas fortes nas variaveis `ADMIN_SENHA` e `ESTOQUE_SENHA`.
- Configure `ALLOWED_ORIGIN` com o dominio real do frontend.
- Para WebAuthn/passkeys fora de `localhost`, use HTTPS.
- Garanta backup periodico do arquivo SQLite definido em `DATABASE_PATH`.
- Verifique se as impressoras permitem consulta SNMP pela rede do servidor.
