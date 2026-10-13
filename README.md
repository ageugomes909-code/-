# davi-api

API básica em Node.js + Express, preparada para deploy no Northflank.

## Executar localmente
```bash
npm install
npm start
```

## Rotas
- `/` página de estado do servidor
- `/health` verificação de saúde em JSON
- `/api` informações da API

O servidor usa `process.env.PORT`, conforme esperado em plataformas de hospedagem.
