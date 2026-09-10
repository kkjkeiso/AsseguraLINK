const SUSPICIOUS_TLDS = new Set([
  "zip",
  "mov",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "xyz",
  "top",
  "click",
  "link",
  "work",
  "rest",
  "country",
  "loan",
  "win",
  "review",
  "surf",
  "cam",
  "cfd"
]);

const SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "cutt.ly",
  "rebrand.ly",
  "shorturl.at",
  "rb.gy",
  "tiny.cc"
]);

const SUSPICIOUS_KEYWORDS = [
  "login",
  "signin",
  "sign-in",
  "verify",
  "verification",
  "account",
  "update",
  "secure",
  "wallet",
  "password",
  "bank",
  "paypal",
  "invoice",
  "confirm",
  "unlock",
  "support",
  "alert"
];

function looksLikeIpv4(host) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function looksLikeIpv6(host) {
  return host.includes(":");
}

function getRegistrableHint(hostname) {
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length < 2) {
    return hostname;
  }
  return parts.slice(-2).join(".");
}

function runHeuristics(rawUrl) {
  const reasons = [];
  let parsed;

  try {
    parsed = new URL(rawUrl);
  } catch {
    reasons.push({
      safe: false,
      text: "O valor informado não corresponde a um endereço URL válido."
    });
    return { parsed: null, reasons };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    reasons.push({
      safe: false,
      text: `O protocolo ${parsed.protocol} não é suportado. A análise aceita apenas HTTP e HTTPS.`
    });
    return { parsed: null, reasons };
  }

  const hostname = parsed.hostname.toLowerCase();
  const href = parsed.href;

  if (parsed.protocol === "https:") {
    reasons.push({
      safe: true,
      text: "A conexão utiliza HTTPS."
    });
  } else {
    reasons.push({
      safe: false,
      text: "A conexão não utiliza HTTPS. O tráfego pode ser interceptado ou alterado."
    });
  }

  if (href.length <= 80) {
    reasons.push({
      safe: true,
      text: "O comprimento da URL está dentro de um intervalo usual."
    });
  } else if (href.length > 180) {
    reasons.push({
      safe: false,
      text: `A URL possui comprimento elevado (${href.length} caracteres), o que pode ocultar parâmetros ou redirecionamentos.`
    });
  } else {
    reasons.push({
      safe: false,
      text: `A URL possui comprimento acima do usual (${href.length} caracteres).`
    });
  }

  if (looksLikeIpv4(hostname) || looksLikeIpv6(hostname)) {
    reasons.push({
      safe: false,
      text: "O destino é um endereço IP, e não um nome de domínio registrado."
    });
  } else {
    reasons.push({
      safe: true,
      text: "O destino utiliza um nome de domínio, e não um endereço IP."
    });
  }

  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    reasons.push({
      safe: false,
      text: "O domínio utiliza punycode (xn--), recurso que pode mascarar caracteres semelhantes a marcas conhecidas."
    });
  }

  if (parsed.username || parsed.password || href.includes("@")) {
    reasons.push({
      safe: false,
      text: "A URL contém credenciais ou o caractere @, o que pode ocultar o destino efetivo."
    });
  }

  const labels = hostname.split(".").filter(Boolean);
  if (labels.length >= 5) {
    reasons.push({
      safe: false,
      text: "O hostname possui um número elevado de subdomínios."
    });
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    reasons.push({
      safe: false,
      text: "O domínio contém múltiplos hífens, padrão associado a imitações de marcas."
    });
  }

  const tld = labels.at(-1) || "";
  if (SUSPICIOUS_TLDS.has(tld)) {
    reasons.push({
      safe: false,
      text: `A extensão .${tld} é frequentemente utilizada em campanhas de phishing e distribuição de malware.`
    });
  }

  const registrable = getRegistrableHint(hostname);
  if (SHORTENERS.has(registrable)) {
    reasons.push({
      safe: false,
      text: "A URL utiliza um serviço de encurtamento. O destino final não é visível nesta etapa."
    });
  }

  const haystack = `${hostname}${parsed.pathname}${parsed.search}`.toLowerCase();
  const keywordHits = SUSPICIOUS_KEYWORDS.filter((word) => haystack.includes(word));
  if (keywordHits.length >= 2) {
    reasons.push({
      safe: false,
      text: `O caminho contém termos frequentemente associados a páginas fraudulentas (${keywordHits.slice(0, 4).join(", ")}).`
    });
  }

  if (parsed.port && !["", "80", "443"].includes(parsed.port)) {
    reasons.push({
      safe: false,
      text: `A URL utiliza a porta ${parsed.port}, diferente das portas padrão 80 e 443.`
    });
  }

  const encodedCount = (href.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (encodedCount >= 8) {
    reasons.push({
      safe: false,
      text: "A URL contém um volume elevado de caracteres percentualmente codificados."
    });
  }

  if (/\.(exe|scr|js|bat|cmd|msi|apk)(?:$|\?)/i.test(parsed.pathname)) {
    reasons.push({
      safe: false,
      text: "O caminho aponta para um arquivo executável."
    });
  }

  return { parsed, reasons };
}

module.exports = { runHeuristics };
