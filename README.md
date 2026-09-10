# AsseguraLINK

Site simples de verificação de links. O usuário cola um endereço, e o resultado lista em verde e vermelho os motivos pelos quais o link aparenta ser seguro ou não.

Não há login.

## Estrutura

```
AsseguraLINK/
  index.html
  css/style.css
  js/script.js
  backend/
    server.js
    src/heuristics.js
    src/apis.js
    .env.example
```

O backend entrega a página única e a API `POST /api/verificar`.

## Checagens

Regras próprias:

- protocolo diferente de HTTPS
- URL longa demais
- IP no lugar de domínio
- `@` na URL
- punycode / hífens / subdomínios excessivos
- encurtadores, TLDs suspeitos, termos de golpe, arquivos executáveis

APIs prontas:

- [Sinking Yachts](https://phish.sinking.yachts/) (phishing, sem chave)
- [Google Safe Browsing](https://developers.google.com/safe-browsing) (opcional, chave no `.env`)
- [URLhaus / abuse.ch](https://urlhaus-api.abuse.ch/) (opcional, chave no `.env`)

## Como rodar

```bash
cd backend
node server.js
```

Abra `http://localhost:3000`.

Para as APIs opcionais, copie `backend/.env.example` para `backend/.env` e preencha as chaves.
