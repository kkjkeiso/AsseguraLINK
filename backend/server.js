const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");
const { runHeuristics } = require("./src/heuristics");
const { runExternalChecks } = require("./src/apis");

loadEnv(path.join(__dirname, ".env"));

const PORT = Number(process.env.PORT) || 3000;
const rootDir = path.join(__dirname, "..");
const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8"
};

function loadEnv(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const text = fs.readFileSync(filePath, "utf8");
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const index = trimmed.indexOf("=");
    if (index === -1) {
      continue;
    }
    const key = trimmed.slice(0, index).trim();
    const value = trimmed.slice(index + 1).trim();
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  res.end(body);
}

function sendFile(res, filePath) {
  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Arquivo não encontrado");
      return;
    }

    const type = mimeTypes[path.extname(filePath)] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": type });
    res.end(data);
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => {
      chunks.push(chunk);
      if (Buffer.concat(chunks).length > 16 * 1024) {
        reject(new Error("body_too_large"));
      }
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function normalizeInput(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    return "";
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

function buildVerdict(reasons) {
  const riskCount = reasons.filter((item) => !item.safe).length;
  const apiRisk = reasons.some(
    (item) =>
      !item.safe && /Safe Browsing|URLhaus|Sinking Yachts/i.test(item.text)
  );

  if (apiRisk || riskCount >= 3) {
    return {
      verdict: "risco",
      summary: "Foram identificados indicadores relevantes de risco neste endereço."
    };
  }

  if (riskCount > 0) {
    return {
      verdict: "atencao",
      summary: "Foram identificados indicadores de risco. Consulte os itens destacados abaixo."
    };
  }

  return {
    verdict: "seguro",
    summary: "Não foram identificados indicadores relevantes de risco nesta análise."
  };
}

async function handleVerify(req, res) {
  let payload;
  try {
    payload = JSON.parse((await readBody(req)) || "{}");
  } catch {
    sendJson(res, 400, { error: "JSON inválido." });
    return;
  }

  const normalized = normalizeInput(payload.url);
  if (!normalized) {
    sendJson(res, 400, { error: "Informe um endereço URL para análise." });
    return;
  }

  const { parsed, reasons } = runHeuristics(normalized);
  if (!parsed) {
    sendJson(res, 200, {
      url: normalized,
      verdict: "risco",
      summary: "Não foi possível analisar o endereço informado.",
      reasons
    });
    return;
  }

  const apiResults = await runExternalChecks(parsed.href, parsed.hostname);
  const combined = [...reasons, ...apiResults.flatMap((item) => item.reasons)];
  const { verdict, summary } = buildVerdict(combined);

  sendJson(res, 200, {
    url: parsed.href,
    verdict,
    summary,
    reasons: combined,
    apis: apiResults
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (req.method === "POST" && url.pathname === "/api/verificar") {
    try {
      await handleVerify(req, res);
    } catch {
      sendJson(res, 500, { error: "Falha interna na verificação." });
    }
    return;
  }

  if (req.method !== "GET") {
    res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Método não permitido");
    return;
  }

  if (url.pathname === "/") {
    sendFile(res, path.join(rootDir, "index.html"));
    return;
  }

  if (url.pathname.startsWith("/css/")) {
    sendFile(res, path.join(rootDir, "css", path.basename(url.pathname)));
    return;
  }

  if (url.pathname.startsWith("/js/")) {
    sendFile(res, path.join(rootDir, "js", path.basename(url.pathname)));
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Não encontrado");
});

server.listen(PORT, () => {
  console.log(`AsseguraLINK em http://localhost:${PORT}`);
});
