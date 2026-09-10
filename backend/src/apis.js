const SINKING_YACHTS_URL = "https://phish.sinking.yachts/v2/check";
const URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/";
const SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

async function fetchJson(url, options, timeoutMs = 7000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }
    return { ok: response.ok, status: response.status, data };
  } finally {
    clearTimeout(timer);
  }
}

async function checkSinkingYachts(hostname) {
  try {
    const result = await fetchJson(`${SINKING_YACHTS_URL}/${encodeURIComponent(hostname)}`, {
      headers: {
        Accept: "application/json",
        "X-Identity": "AsseguraLINK (verificacao de links)"
      }
    });

    if (!result.ok) {
      return {
        source: "Sinking Yachts",
        available: false,
        reasons: []
      };
    }

    const listed = result.data === true || result.data === "true";
    return {
      source: "Sinking Yachts",
      available: true,
      reasons: listed
        ? [
            {
              safe: false,
              text: "A base Sinking Yachts classifica este domínio como phishing conhecido."
            }
          ]
        : [
            {
              safe: true,
              text: "O domínio não consta na base pública de phishing da Sinking Yachts."
            }
          ]
    };
  } catch {
    return { source: "Sinking Yachts", available: false, reasons: [] };
  }
}

async function checkUrlhaus(url, authKey) {
  if (!authKey) {
    return { source: "URLhaus", available: false, reasons: [] };
  }

  try {
    const body = new URLSearchParams({ url });
    const result = await fetchJson(URLHAUS_URL, {
      method: "POST",
      headers: {
        "Auth-Key": authKey,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    });

    if (!result.ok || !result.data || typeof result.data !== "object") {
      return { source: "URLhaus", available: false, reasons: [] };
    }

    if (result.data.query_status === "ok") {
      const threat = result.data.threat || "malware";
      return {
        source: "URLhaus",
        available: true,
        reasons: [
          {
            safe: false,
            text: `A base URLhaus (abuse.ch) registra este endereço como distribuição de malware (${threat}).`
          }
        ]
      };
    }

    if (result.data.query_status === "no_results") {
      return {
        source: "URLhaus",
        available: true,
        reasons: [
          {
            safe: true,
            text: "O endereço não consta na base URLhaus de distribuição de malware."
          }
        ]
      };
    }

    return { source: "URLhaus", available: false, reasons: [] };
  } catch {
    return { source: "URLhaus", available: false, reasons: [] };
  }
}

async function checkSafeBrowsing(url, apiKey) {
  if (!apiKey) {
    return { source: "Google Safe Browsing", available: false, reasons: [] };
  }

  try {
    const result = await fetchJson(`${SAFE_BROWSING_URL}?key=${encodeURIComponent(apiKey)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: {
          clientId: "asseguralink",
          clientVersion: "1.0.0"
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      })
    });

    if (!result.ok || typeof result.data !== "object") {
      return { source: "Google Safe Browsing", available: false, reasons: [] };
    }

    const matches = Array.isArray(result.data.matches) ? result.data.matches : [];
    if (matches.length > 0) {
      const types = [...new Set(matches.map((item) => item.threatType).filter(Boolean))];
      return {
        source: "Google Safe Browsing",
        available: true,
        reasons: [
          {
            safe: false,
            text: `O Google Safe Browsing classifica este endereço como ameaça (${types.join(", ") || "não especificada"}).`
          }
        ]
      };
    }

    return {
      source: "Google Safe Browsing",
      available: true,
      reasons: [
        {
          safe: true,
          text: "O Google Safe Browsing não identificou malware, software indesejado ou engenharia social neste endereço."
        }
      ]
    };
  } catch {
    return { source: "Google Safe Browsing", available: false, reasons: [] };
  }
}

async function runExternalChecks(url, hostname) {
  const [sinking, urlhaus, safeBrowsing] = await Promise.all([
    checkSinkingYachts(hostname),
    checkUrlhaus(url, process.env.ABUSECH_AUTH_KEY),
    checkSafeBrowsing(url, process.env.GOOGLE_SAFE_BROWSING_API_KEY)
  ]);

  return [sinking, urlhaus, safeBrowsing];
}

module.exports = { runExternalChecks };
