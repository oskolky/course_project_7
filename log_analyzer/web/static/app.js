const state = { datasets: [], currentDataset: null, currentRun: null };
const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const severityNames = { critical: "Критическая", high: "Высокая", medium: "Средняя", low: "Низкая" };
const runNames = { pending: "В очереди", running: "Анализ выполняется", completed: "Анализ завершён", failed: "Ошибка анализа" };
let toastTimer;

function toast(message, error = false) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.toggle("error", error);
  node.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove("visible"), 4200);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const type = response.headers.get("content-type") || "";
  const payload = type.includes("json") ? await response.json() : await response.text();
  if (!response.ok) {
    const detail = typeof payload === "object" ? payload.detail : payload;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return payload;
}

function busy(button, active) {
  if (active) {
    button.dataset.label = button.textContent;
    button.disabled = true;
    button.textContent = "Выполняется…";
  } else {
    button.disabled = false;
    button.textContent = button.dataset.label || button.textContent;
  }
}

async function refreshDatasets() {
  state.datasets = await api("/api/datasets");
  const select = $("#dataset-select");
  select.disabled = !state.datasets.length;
  select.innerHTML = state.datasets.length
    ? state.datasets.map((item) => `<option value="${esc(item.id)}">${esc(item.name)} · ${esc(item.stats.normalized_count ?? 0)} записей</option>`).join("")
    : '<option value="">Нет наборов</option>';
  if (state.currentDataset) select.value = state.currentDataset;
}

async function loadDataset(datasetId, runId = null) {
  if (!datasetId) return;
  state.currentDataset = datasetId;
  $("#dataset-select").value = datasetId;
  const params = new URLSearchParams({ dataset_id: datasetId });
  if (runId) params.set("run_id", runId);
  const overview = await api(`/api/overview?${params}`);
  state.currentRun = overview.run;
  renderOverview(overview);
  await loadIncidents();
  const dataset = state.datasets.find((item) => item.id === datasetId) || await api(`/api/datasets/${datasetId}`);
  const stats = dataset.stats || {};
  $("#dataset-meta").textContent = `Обработано: ${stats.normalized_count ?? 0} · Отклонено: ${stats.rejected_count ?? 0}`;
}

function renderOverview(data) {
  const summary = data.summary;
  $("#metric-events").textContent = summary.events;
  $("#metric-incidents").textContent = summary.incidents;
  $("#metric-review").textContent = summary.review_required;
  $("#metric-errors").textContent = percent(summary.max_error_ratio);
  renderRunStatus(data.run);
  const warnings = data.run?.warnings || [];
  const warningBox = $("#run-warnings");
  warningBox.hidden = !warnings.length && !data.run?.error;
  warningBox.textContent = [data.run?.error, ...warnings].filter(Boolean).join("\n");
}

function renderRunStatus(run) {
  const badge = $("#run-status");
  badge.className = `status-badge ${run?.status || ""}`;
  badge.textContent = run ? runNames[run.status] || run.status : "Нет данных";
}

async function loadIncidents() {
  if (!state.currentDataset) return;
  const params = new URLSearchParams({ dataset_id: state.currentDataset });
  if (state.currentRun?.id) params.set("run_id", state.currentRun.id);
  const incidents = await api(`/api/incidents?${params}`);
  $("#incident-count").textContent = `${incidents.length} записей`;
  if (!incidents.length) {
    $("#incidents-body").innerHTML = '<tr><td colspan="5" class="empty-cell">Инциденты не обнаружены.</td></tr>';
    return;
  }
  $("#incidents-body").innerHTML = incidents.map((incident) => `<tr>
    <td class="time-cell">${esc(formatTime(incident.window_start))}</td>
    <td><strong>${esc(incident.hypothesis || "Неподтверждённое отклонение")}</strong></td>
    <td><strong>${esc(incident.service || "—")}</strong><small>${esc(incident.route || "Маршрут не определён")}</small></td>
    <td><span class="severity ${esc(incident.severity)}">${esc(severityNames[incident.severity] || incident.severity)}</span></td>
    <td><button class="row-button" type="button" data-incident="${esc(incident.incident_id)}">Подробнее</button></td>
  </tr>`).join("");
}

async function openIncident(id) {
  const incident = await api(`/api/incidents/${id}`);
  const facts = [
    ["Интервал", `${formatTime(incident.window_start)} — ${formatTime(incident.window_end)}`],
    ["Сервис", incident.service || "—"],
    ["Маршрут", incident.route || "—"],
    ["Запросы", incident.features.n_req ?? "—"],
    ["4xx / 5xx", `${percent(incident.features.r_4xx)} / ${percent(incident.features.r_5xx)}`],
  ];
  const evidence = (incident.evidence || []).map((item) => `<details class="evidence-item"><summary>${esc(item.event.source.service)} · ${esc(formatTime(item.event.observed_at))}</summary><pre>${esc(item.excerpt)}</pre></details>`).join("") || '<p class="muted">Нет связанных записей.</p>';
  $("#incident-detail").innerHTML = `
    <div class="detail-heading">
      <span class="severity ${esc(incident.severity)}">${esc(severityNames[incident.severity] || incident.severity)}</span>
      <h3>${esc(incident.hypothesis || "Неподтверждённое отклонение")}</h3>
      ${incident.review_required ? '<p class="review-flag">Требуется ручная проверка</p>' : ""}
    </div>
    <section class="detail-section"><h4>Наблюдаемые факты</h4><dl class="fact-list">${facts.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`).join("")}</dl></section>
    <section class="detail-section"><h4>Рекомендация</h4><p>${esc(incident.recommendation || "Исследуйте связанные события.")}</p>${incident.review_required ? `<button class="button secondary full" id="review-button" type="button">${incident.reviewed_at ? "Проверено — отметить снова" : "Отметить как проверенное"}</button>` : ""}</section>
    <section class="detail-section"><h4>Связанные записи · ${incident.evidence?.length || 0}</h4>${evidence}</section>`;
  const review = $("#review-button");
  if (review) review.addEventListener("click", async () => {
    review.disabled = true;
    try {
      await api(`/api/incidents/${incident.incident_id}/review`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reviewed: true }) });
      toast("Результат проверки сохранён");
      await openIncident(incident.incident_id);
    } catch (error) {
      review.disabled = false;
      toast(error.message, true);
    }
  });
  if (!$("#incident-dialog").open) $("#incident-dialog").showModal();
}

function percent(value) {
  return `${(Number(value || 0) * 100).toFixed(1)}%`;
}

function formatTime(value) {
  return value ? new Date(value).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
}

async function pollRun(runId) {
  for (let attempt = 0; attempt < 120; attempt++) {
    const run = await api(`/api/runs/${runId}`);
    state.currentRun = run;
    renderRunStatus(run);
    if (run.status === "completed") {
      await refreshDatasets();
      await loadDataset(run.dataset_id, run.id);
      toast(`Анализ завершён: ${run.stats.incidents} инцидентов`);
      return;
    }
    if (run.status === "failed") {
      await loadDataset(run.dataset_id, run.id);
      throw new Error(run.error || "Ошибка анализа");
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("Превышено время ожидания анализа");
}

$("#demo-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  busy(button, true);
  try {
    const result = await api("/api/demo", { method: "POST" });
    state.currentDataset = result.dataset.id;
    state.currentRun = result.run;
    await refreshDatasets();
    await loadDataset(result.dataset.id, result.run.id);
    await pollRun(result.run.id);
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(button, false);
  }
});

$("#upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button[type=submit]");
  busy(button, true);
  try {
    const form = new FormData(event.currentTarget);
    form.set("service", form.get("service")?.trim() || "unknown");
    form.set("analyze", "true");
    const result = await api("/api/datasets", { method: "POST", body: form });
    state.currentDataset = result.dataset.id;
    state.currentRun = result.run;
    await refreshDatasets();
    await loadDataset(result.dataset.id, result.run.id);
    await pollRun(result.run.id);
    event.currentTarget.reset();
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(button, false);
  }
});

$("#dataset-select").addEventListener("change", async (event) => {
  $("#incident-dialog").close();
  try {
    await loadDataset(event.target.value);
  } catch (error) {
    toast(error.message, true);
  }
});

$("#incidents-body").addEventListener("click", (event) => {
  const button = event.target.closest("[data-incident]");
  if (button) openIncident(button.dataset.incident).catch((error) => toast(error.message, true));
});

$("#close-incident").addEventListener("click", () => $("#incident-dialog").close());
$("#incident-dialog").addEventListener("click", (event) => {
  if (event.target === event.currentTarget) event.currentTarget.close();
});

(async function init() {
  try {
    await api("/api/health");
    await refreshDatasets();
    if (state.datasets.length) await loadDataset(state.datasets[0].id);
  } catch (error) {
    toast(error.message, true);
  }
})();
