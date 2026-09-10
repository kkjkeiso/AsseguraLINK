const VERDICT_LABELS = {
  seguro: "Endereço seguro",
  atencao: "Atenção",
  risco: "Risco identificado"
};

const form = document.getElementById("check-form");
const input = document.getElementById("url-input");
const button = document.getElementById("submit-btn");
const result = document.getElementById("result");
const title = document.getElementById("result-title");
const summaryEl = document.getElementById("result-summary");
const urlLine = document.getElementById("result-url");
const reasonsList = document.getElementById("reasons");
const apiSourcesEl = document.getElementById("api-sources");
const apiCardsEl = document.getElementById("api-cards");

function renderApiSources(apis) {
  if (!apis || apis.length === 0) return;
  apiSourcesEl.hidden = false;
  apiCardsEl.replaceChildren();

  for (const api of apis) {
    const card = document.createElement("div");
    card.className = "api-card";

    const name = document.createElement("p");
    name.className = "api-name";
    name.textContent = api.source;
    card.appendChild(name);

    if (!api.available) {
      const status = document.createElement("p");
      status.className = "api-status unavailable";
      status.textContent = "API não configurada";
      card.appendChild(status);
    } else {
      for (const reason of api.reasons) {
        const status = document.createElement("p");
        status.className = `api-status ${reason.safe ? "ok" : "risk"}`;
        status.textContent = reason.text;
        card.appendChild(status);
      }
    }

    apiCardsEl.appendChild(card);
  }
}

function render(data) {
  result.hidden = false;
  result.className = `result ${data.verdict || ""}`;
  title.textContent = VERDICT_LABELS[data.verdict] || data.verdict || "Erro";
  summaryEl.textContent = data.summary || data.error || "";
  urlLine.textContent = data.url || "";
  reasonsList.replaceChildren();

  for (const reason of data.reasons || []) {
    const item = document.createElement("li");
    item.className = reason.safe ? "ok" : "risk";
    item.textContent = reason.text;
    reasonsList.appendChild(item);
  }

  renderApiSources(data.apis);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  button.textContent = "Analisando...";

  // Oculta resultado anterior enquanto carrega
  result.hidden = true;
  result.className = "result";
  reasonsList.replaceChildren();
  apiSourcesEl.hidden = true;
  apiCardsEl.replaceChildren();

  try {
    const response = await fetch("/api/verificar", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: input.value })
    });
    const data = await response.json();
    render(data);
  } catch {
    render({
      verdict: "risco",
      summary: "Não foi possível concluir a análise neste momento.",
      reasons: [
        {
          safe: false,
          text: "O serviço de análise está indisponível. Verifique se o backend está em execução."
        }
      ]
    });
  } finally {
    button.disabled = false;
    button.textContent = "Analisar";
  }
});
