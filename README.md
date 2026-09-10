# AsseguraLINK

Ferramenta web para verificação de segurança de links. O usuário informa um endereço URL e recebe uma análise detalhada, combinando heurísticas técnicas locais com consultas a bases públicas de phishing e malware.

## Como funciona

A análise acontece em duas etapas:

1. **Heurísticas locais** — a URL é avaliada segundo critérios técnicos conhecidos por indicar risco: protocolo, formato do domínio, comprimento, uso de encurtadores, entre outros.
2. **Consulta a bases externas** — a mesma URL é verificada em paralelo contra bases públicas de ameaças conhecidas.

O resultado combina os dois lados: uma lista de motivos (seguros e de risco) à esquerda, e a origem de cada fonte consultada à direita.

## Critérios de análise

**Heurísticas locais:**
- Protocolo diferente de HTTPS
- IP no lugar de domínio registrado
- Uso de punycode, excesso de hífens ou subdomínios
- Comprimento incomum da URL ou volume elevado de caracteres codificados
- Credenciais ou `@` embutidos na URL
- Encurtadores de link, TLDs associadas a abuso, termos comuns em golpes
- Porta não padrão ou extensão de arquivo executável

**Bases externas consultadas:**
| Fonte | Cobertura | Autenticação |
|---|---|---|
| [Sinking Yachts](https://phish.sinking.yachts/) | Phishing | Não requer chave |
| [Google Safe Browsing](https://developers.google.com/safe-browsing) | Malware, engenharia social, software indesejado | Chave de API (opcional) |
| [URLhaus (abuse.ch)](https://urlhaus-api.abuse.ch/) | Distribuição de malware | Chave de API (opcional) |

## Stack

Sem frameworks ou dependências externas — HTML, CSS e JavaScript puros no frontend, Node.js nativo (`http`) no backend.

```
AsseguraLINK/
├── index.html
├── css/style.css
├── js/script.js
└── backend/
    ├── server.js
    ├── src/heuristics.js
    ├── src/apis.js
    └── .env.example
```

## Como rodar

Requer Node.js 18+.

```bash
cd backend
node server.js
```

Acesse `http://localhost:3000`.

### Configuração opcional

Para habilitar Google Safe Browsing e URLhaus, copie o arquivo de exemplo e preencha suas chaves:

```bash
cp backend/.env.example backend/.env
```

| Variável | Descrição |
|---|---|
| `PORT` | Porta do servidor (padrão `3000`) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Chave da API do Google Safe Browsing |
| `ABUSECH_AUTH_KEY` | Chave de autenticação do URLhaus / abuse.ch |

Sem essas chaves, a aplicação funciona normalmente com as heurísticas locais e a base Sinking Yachts.

## API

```
POST /api/verificar
Content-Type: application/json

{ "url": "https://exemplo.com" }
```

Retorna o veredito (`seguro`, `atencao` ou `risco`), a lista de motivos identificados e o detalhamento por fonte consultada.
