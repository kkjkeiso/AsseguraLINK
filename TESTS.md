# AsseguraLINK — Guia de Testes

Este documento reúne roteiros e links prontos para testar o **AsseguraLINK**: a heurística local (`backend/src/heuristics.js`), a integração com as bases externas (`backend/src/apis.js`) e, em especial, os **URLs oficiais de teste do Google Safe Browsing**, que replicam exatamente os `threatTypes` consultados pela aplicação.

> ⚠️ Todos os links deste documento são recursos de teste **oficiais e inofensivos**, publicados pelo próprio Google (`testsafebrowsing.appspot.com`) ou domínios reservados para documentação (`example.com`, faixas `TEST-NET`). Nenhum deles aponta para conteúdo malicioso real.

## Sumário

1. [Executando a aplicação](#1-executando-a-aplicação)
2. [Testes da API direta (curl)](#2-testes-da-api-direta-curl)
3. [Casos de teste — heurísticas locais](#3-casos-de-teste--heurísticas-locais)
4. [Google Safe Browsing — URLs oficiais de teste](#4-google-safe-browsing--urls-oficiais-de-teste)
5. [URLhaus e Sinking Yachts](#5-urlhaus-e-sinking-yachts)
6. [Roteiro de teste manual](#6-roteiro-de-teste-manual)
7. [Referências](#7-referências)

---

## 1. Executando a aplicação

```bash
cd backend
node server.js
```

Acesse `http://localhost:3000`. Para habilitar Google Safe Browsing e URLhaus, preencha `backend/.env` (ver `backend/.env.example`) — sem as chaves, a aplicação segue funcional usando heurísticas locais + Sinking Yachts.

## 2. Testes da API direta (curl)

```bash
curl -X POST http://localhost:3000/api/verificar \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Troque o valor de `url` por qualquer um dos links das seções seguintes para validar o veredito (`seguro`, `atencao` ou `risco`).

## 3. Casos de teste — heurísticas locais

Exemplos construídos sobre domínios/IPs reservados para documentação (RFC 2606 e RFC 5737), então não dependem de nenhum site de terceiros real.

| Critério avaliado (`heuristics.js`) | Resultado esperado | URL de exemplo |
|---|---|---|
| HTTPS presente | seguro | `https://example.com/` |
| Ausência de HTTPS | risco | `http://example.com/` |
| Domínio (não IP) | seguro | `https://example.com/` |
| Destino é endereço IPv4 | risco | `http://203.0.113.10/` |
| Destino é endereço IPv6 | risco | `http://[2001:db8::1]/` |
| Punycode (`xn--`) | risco | `https://xn--exemplo-8xa.com/` |
| Credenciais / `@` na URL | risco | `https://user:pass@example.com/` |
| Excesso de subdomínios (≥5 rótulos) | risco | `https://a.b.c.d.example.com/` |
| Excesso de hífens (≥3) | risco | `https://minha-conta-segura-login.com/` |
| TLD suspeita (`.zip`, `.tk`, `.xyz`, `.top`, etc.) | risco | `https://exemplo.xyz/` |
| Encurtador de link | risco | `https://bit.ly/3exemplo` |
| Palavras-chave suspeitas (≥2, ex.: `login`, `verify`, `account`) | risco | `https://example.com/login/verify-account` |
| Porta não padrão | risco | `https://example.com:8443/` |
| Excesso de caracteres percent-encoded (≥8) | risco | `https://example.com/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f` |
| Extensão de arquivo executável | risco | `https://example.com/setup.exe` |
| URL muito longa (>180 caracteres) | risco | `https://example.com/` + query longa (ex.: repetir `?a=1` várias vezes) |
| URL inválida / protocolo não suportado | risco | `ftp://example.com/` |

## 4. Google Safe Browsing — URLs oficiais de teste

O Google mantém um serviço público (`testsafebrowsing.appspot.com`) com URLs de teste que sempre retornam positivo nas categorias correspondentes — feito exatamente para validar integrações como a deste projeto (`backend/src/apis.js`, função `checkSafeBrowsing`, endpoint `threatMatches:find`).

### 4.1 API v4 (`threatMatches:find`) — mapeiam direto para os `threatTypes` consultados pela aplicação

Cole qualquer um destes valores no campo de análise do AsseguraLINK (com a chave `GOOGLE_SAFE_BROWSING_API_KEY` configurada) para forçar o veredito **risco**:

| threatType consultado pela app | URL de teste oficial |
|---|---|
| `MALWARE` | `https://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/` |
| `SOCIAL_ENGINEERING` | `https://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/` |
| `UNWANTED_SOFTWARE` | `https://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/UNWANTED_SOFTWARE/URL/` |
| `POTENTIALLY_HARMFUL_APPLICATION`* | `https://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/POTENTIALLY_HARMFUL_APPLICATION/URL/` |

\* Categoria voltada principalmente a apps Android; a variante `ANY_PLATFORM` é menos documentada e pode não retornar `match` em todos os ambientes — nesse caso use as variantes por plataforma abaixo.

Variantes específicas por plataforma (também aceitas pela API, úteis se `POTENTIALLY_HARMFUL_APPLICATION` acima não responder):

| Plataforma / ameaça | URL de teste oficial |
|---|---|
| iOS · Malware | `https://testsafebrowsing.appspot.com/apiv4/IOS/MALWARE/URL/` |
| iOS · Engenharia social | `https://testsafebrowsing.appspot.com/apiv4/IOS/SOCIAL_ENGINEERING_INTERNAL/URL/` |
| macOS · Malware | `https://testsafebrowsing.appspot.com/apiv4/OSX/MALWARE/URL/` |
| macOS · Engenharia social | `https://testsafebrowsing.appspot.com/apiv4/OSX/SOCIAL_ENGINEERING_INTERNAL/URL/` |

### 4.2 Páginas de aviso do navegador (interstitial — teste visual, fora da app)

Úteis para comparar o veredito do AsseguraLINK com o comportamento real do Chrome/Edge ao abrir o mesmo link:

| Página | Categoria |
|---|---|
| `https://testsafebrowsing.appspot.com/s/phishing.html` | Phishing |
| `https://testsafebrowsing.appspot.com/s/malware.html` | Malware |
| `https://testsafebrowsing.appspot.com/s/malware_in_iframe.html` | Malware (subrecurso) |
| `https://testsafebrowsing.appspot.com/s/unwanted.html` | Software indesejado |
| `https://testsafebrowsing.appspot.com/s/trick_to_bill.html` | Fraude de cobrança |
| `https://testsafebrowsing.appspot.com/s/bad_login.html` | Reutilização de senha / phishing |
| `https://testsafebrowsing.appspot.com/s/suspicious.html` | Suspeita |

### 4.3 Downloads de teste (não recomendado abrir fora de ambiente controlado)

O navegador ou o antivírus deve bloquear/alertar — esse é o comportamento esperado, não um problema:

| Arquivo | Categoria |
|---|---|
| `https://testsafebrowsing.appspot.com/s/content.exe` | Malicioso (simulado) |
| `https://testsafebrowsing.appspot.com/s/badrep.exe` | Reputação ruim |
| `https://testsafebrowsing.appspot.com/s/unknown.exe` | Pouco comum |
| `https://testsafebrowsing.appspot.com/s/pua.exe` | App potencialmente indesejado |

## 5. URLhaus e Sinking Yachts

Essas duas bases não publicam um serviço oficial de "URL de teste sempre positiva" como o Google. Para validar a integração:

- **Caminho negativo (esperado "seguro")**: use `https://example.com/` — não deve constar em nenhuma das duas bases.
- **Caminho positivo**: consulte uma entrada ativa na própria base pública antes do teste — [URLhaus browse](https://urlhaus.abuse.ch/browse/) e [Sinking Yachts stats](https://phish.sinking.yachts/) — e cole a URL listada no momento do teste (essas listas mudam constantemente, por isso não há um link fixo e estável para incluir aqui).
- Sem a chave `ABUSECH_AUTH_KEY`, o `apis.js` já retorna `available: false` para o URLhaus — comportamento esperado, não é falha.

## 6. Roteiro de teste manual

1. Rodar a aplicação localmente (seção 1).
2. Testar 3–4 URLs da tabela de heurísticas (seção 3) e confirmar que os motivos exibidos coincidem com a coluna "Critério avaliado".
3. Configurar `GOOGLE_SAFE_BROWSING_API_KEY` e testar pelo menos um link da tabela 4.1 — confirmar veredito **risco** com a fonte "Google Safe Browsing".
4. Testar `https://example.com/` isoladamente — confirmar veredito **seguro**.
5. (Opcional) Repetir o teste do item 3 sem a chave configurada — confirmar que a fonte aparece como indisponível e o veredito não quebra.
6. Testar uma URL malformada (ex.: `não é url`) e um protocolo não suportado (ex.: `ftp://example.com`) — confirmar tratamento de erro (`400`/veredito `risco` com mensagem apropriada).

## 7. Referências

- [Google Safe Browsing — visão geral da API](https://developers.google.com/safe-browsing)
- [Google Safe Browsing — API v4 threatMatches:find](https://developers.google.com/safe-browsing/v4/lookup-api)
- [testsafebrowsing.appspot.com](https://testsafebrowsing.appspot.com/) — catálogo oficial de URLs de teste do Google
- [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/)
- [Sinking Yachts](https://phish.sinking.yachts/)
- [RFC 2606 — domínios reservados para documentação](https://www.rfc-editor.org/rfc/rfc2606)
- [RFC 5737 — blocos de IPv4 reservados para documentação](https://www.rfc-editor.org/rfc/rfc5737)
