const state = {
  datasets: [], currentDataset: null, currentRun: null, currentModel: null,
  search: { offset: 0, total: 0, limit: 50, active: false, templateId: null },
};
const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const humanize = (id) => String(id ?? "").replace(/_/g, " ");

const severityNames = { critical: "Критическая", high: "Высокая", medium: "Средняя", low: "Низкая" };
const runNames = { queued: "В очереди", pending: "В очереди", running: "Анализ выполняется", completed: "Анализ завершён", failed: "Ошибка анализа" };
const kindNames = {
  known: "Известный сбой: сработало правило базы знаний",
  known_with_anomaly: "Известный сбой: правило подтверждено моделью",
  unknown_anomaly: "Отклонение от обычного поведения, причина не установлена",
  rule_conflict: "Признаки соответствуют нескольким типам ошибок",
};
const kindShort = { known: "правило", known_with_anomaly: "правило и модель", unknown_anomaly: "модель", rule_conflict: "конфликт правил" };
const confidenceNames = {
  rule_confirmed: "Вывод сделан по правилу базы знаний; его можно проверить по условиям правила и исходным записям.",
  model_only: "Результат получен только статистической моделью. Причина отклонения не устанавливалась.",
  rule_conflict: "Правила базы знаний дали разные гипотезы. Однозначный вывод невозможен, нужна ручная проверка.",
};
const hypothesisTitles = {
  authentication_issuer_mismatch: "Несовпадение издателя токена при аутентификации",
  upstream_timeout: "Тайм-аут ответа вышестоящего сервера (upstream)",
  conflicting_rule_hypotheses: "Конфликт правил базы знаний",
};
const recommendationTexts = {
  compare_token_issuer_configuration: "Сверить издателя токенов (issuer) в конфигурации сервиса аутентификации и в приложении.",
  inspect_upstream_health_and_timeout_settings: "Проверить доступность и время ответа upstream, а также настройки тайм-аутов веб-сервера.",
  inspect_feature_values: "Изучить значения признаков окна и связанные записи: причина отклонения правилами не установлена.",
  review_conflicting_rules_and_evidence: "Проверить конфликтующие правила и доказательства, выбрать одну из интерпретаций или отклонить их.",
};
const featureNames = {
  n_req: "число запросов", r_401: "доля ответов 401", r_4xx: "доля ответов 4xx", r_5xx: "доля ответов 5xx",
  q_095_duration_ms: "95-й перцентиль длительности, мс", n_retry: "повторные запросы", n_tpl: "число шаблонов сообщений",
  n_new: "новые шаблоны", r_uncertain: "доля событий без точной связи",
};
const roleNames = { http_response: "ответ HTTP", primary_error: "сообщение об ошибке", context: "контекст окна" };
const reasonNames = {
  no_signals: "Инцидент не создан: признаков ошибок и отклонений не найдено",
  insufficient_data: "Мало данных: анализ не выполнялся",
};
const modelStatusNames = { anomaly: "аномалия", normal: "норма", insufficient_data: "мало данных" };
const sourceNames = { nginx_access: "Доступ NGINX", apache_access: "Доступ Apache", error_log: "Журнал ошибок", application_json: "Приложение" };
const stepKeys = {
  events: "событий", templates: "шаблонов", groups: "групп", windows: "оконов", rules: "действующих правил",
  matches: "срабатываний", status: "состояние", model_id: "модель", anomaly: "аномальных окон",
  normal: "нормальных окон", insufficient_data: "окон с малым числом данных", incidents: "инцидентов",
  evidence: "доказательств",
};
const errorTexts = [
  [/At least two sufficiently populated windows/i, "Для обучения нужно не менее двух окон с достаточным числом запросов. Загрузите более длинный период без сбоев."],
  [/UTF-8 is required/, "Файл должен быть в кодировке UTF-8."],
  [/Upload size limit exceeded/i, "Превышен предел размера загрузки (10 МБ)."],
  [/Dataset not found/i, "Набор данных не найден: возможно, он был удалён."],
  [/Incident not found/i, "Инцидент не найден."],
  [/Model artifact is unavailable|Unknown model/i, "Модель недоступна. Обучите модель заново."],
  [/Simulated model unavailability/i, "Модель недоступна."],
  [/Upload exactly one rule/i, "За один раз можно опубликовать только одно правило."],
];
let toastTimer;

function friendlyError(message) {
  const text = String(message ?? "").replace(/^\s+/, "");
  for (const [pattern, translation] of errorTexts) {
    if (pattern.test(text)) return translation;
  }
  return text || "Неизвестная ошибка";
}

function toast(message, error = false) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.toggle("error", error);
  node.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove("visible"), 5200);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const type = response.headers.get("content-type") || "";
  const payload = type.includes("json") ? await response.json() : await response.text();
  if (!response.ok) {
    const detail = typeof payload === "object" ? payload.detail : payload;
    throw new Error(friendlyError(typeof detail === "string" ? detail : JSON.stringify(detail)));
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

function plural(count, one, few, many) {
  const absolute = Math.abs(count) % 100;
  const last = absolute % 10;
  if (absolute > 10 && absolute < 20) return many;
  if (last > 1 && last < 5) return few;
  if (last === 1) return one;
  return many;
}
const countLabel = (count, one, few, many) => `${count} ${plural(count, one, few, many)}`;

function percent(value) {
  return `${(Number(value || 0) * 100).toFixed(1)}%`;
}

function formatTime(value) {
  return value ? new Date(value).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
}

function hypothesisTitle(item) {
  return item.title || hypothesisTitles[item.hypothesis] || humanize(item.hypothesis);
}

function incidentTitle(incident) {
  if (incident.kind === "unknown_anomaly") return "Отклонение от обычного поведения";
  if (incident.kind === "rule_conflict") {
    const titles = (incident.hypotheses || []).map(hypothesisTitle);
    return titles.length > 1 ? `Конфликт правил: ${titles.join(" или ")}` : "Конфликт правил базы знаний";
  }
  const titled = (incident.hypotheses || []).find((item) => item.title);
  return titled?.title || hypothesisTitles[incident.hypothesis] || humanize(incident.hypothesis) || "Инцидент";
}

function recommendationText(incident) {
  return incident.recommendation_text || recommendationTexts[incident.recommendation] || humanize(incident.recommendation);
}

async function refreshDatasets() {
  state.datasets = await api("/api/datasets");
  const select = $("#dataset-select");
  select.disabled = !state.datasets.length;
  select.innerHTML = state.datasets.length
    ? state.datasets.map((item) => `<option value="${esc(item.id)}">${esc(item.name)} · ${esc(item.stats.normalized_count ?? 0)} ${plural(item.stats.normalized_count ?? 0, "запись", "записи", "записей")}</option>`).join("")
    : '<option value="">Нет наборов</option>';
  if (state.currentDataset) select.value = state.currentDataset;
  updateActionButtons();
}

async function refreshModels() {
  const models = await api("/api/models");
  state.currentModel = models.length ? models[0].id : null;
  updateActionButtons();
}

function updateActionButtons() {
  const has = Boolean(state.currentDataset);
  $("#delete-dataset-button").disabled = !has;
  $("#train-model-button").disabled = !has;
  $("#analyze-model-button").disabled = !has || !state.currentModel;
  $("#rules-only-button").disabled = !has;
}

function resetResultsView() {
  state.currentRun = null;
  state.search = { offset: 0, total: 0, limit: 50, active: false, templateId: null };
  $("#dataset-meta").textContent = "Загрузите журналы или запустите демонстрацию.";
  ["#metric-events", "#metric-incidents", "#metric-review", "#metric-insufficient", "#metric-errors"].forEach((id) => { $(id).textContent = "—"; });
  renderRunStatus(null);
  renderNotices([]);
  $("#incident-distribution").hidden = true;
  $("#incident-count").textContent = "0 записей";
  $("#incidents-body").innerHTML = '<tr><td colspan="6" class="empty-cell">Инциденты появятся после анализа.</td></tr>';
  $("#template-count").textContent = "";
  $("#templates-body").innerHTML = '<tr><td colspan="4" class="empty-cell">Шаблоны появятся после загрузки журналов.</td></tr>';
  $("#protocol-steps").hidden = true;
  $("#protocol-steps").innerHTML = "";
  $("#protocol-body").innerHTML = '<tr><td colspan="8" class="empty-cell">Протокол появится после анализа.</td></tr>';
  resetSearchView();
  $("#incident-dialog").close();
}

async function loadDataset(datasetId, runId = null) {
  if (!datasetId) return;
  state.currentDataset = datasetId;
  $("#dataset-select").value = datasetId;
  const params = new URLSearchParams({ dataset_id: datasetId });
  if (runId) params.set("run_id", runId);
  const [overview, templates] = await Promise.all([
    api(`/api/overview?${params}`),
    api(`/api/templates?dataset_id=${encodeURIComponent(datasetId)}&limit=15`),
  ]);
  state.currentRun = overview.run;
  renderOverview(overview);
  renderTemplates(templates);
  await loadIncidents();
  const dataset = state.datasets.find((item) => item.id === datasetId) || await api(`/api/datasets/${datasetId}`);
  renderDatasetMeta(dataset);
  updateActionButtons();
  await loadProtocol();
  if (state.search.active) await runSearch();
}

function renderDatasetMeta(dataset) {
  const stats = dataset.stats || {};
  const parts = [
    `Обработано: ${stats.normalized_count ?? 0}`,
    `Отклонено: ${stats.rejected_count ?? 0}`,
    `Шаблонов: ${stats.template_count ?? 0}`,
    `Окнов: ${stats.window_count ?? 0}`,
  ];
  const issues = (stats.issues || []).slice(0, 8);
  $("#dataset-meta").innerHTML = `${esc(parts.join(" · "))}` + (issues.length
    ? `<ul class="issue-list">${issues.map((issue) => `<li>${esc(issue.source)}, строка ${esc(issue.line_number)}: ${esc(issue.error)}${issue.detail ? ` <span class="muted">(${esc(truncate(issue.detail, 120))})</span>` : ""}</li>`).join("")}${(stats.issues || []).length > issues.length ? `<li class="muted">и ещё ${stats.issues.length - issues.length}</li>` : ""}</ul>`
    : "");
}

function truncate(value, limit) {
  const text = String(value ?? "");
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}

function renderOverview(data) {
  const summary = data.summary;
  $("#metric-events").textContent = summary.events;
  $("#metric-incidents").textContent = summary.incidents;
  $("#metric-review").textContent = summary.review_required;
  $("#metric-insufficient").textContent = summary.insufficient_windows;
  $("#metric-errors").textContent = percent(summary.max_error_ratio);
  renderRunStatus(data.run);
  renderNotices([
    ...(data.notices || []).map((notice) => ({ level: notice.level || "info", text: notice.text })),
    ...((data.run?.warnings || []).map((warning) => ({ level: "warning", text: warning }))),
    ...(data.run?.error ? [{ level: "error", text: friendlyError(data.run.error) }] : []),
  ]);
  renderDistribution(summary);
}

function renderRunStatus(run) {
  const badge = $("#run-status");
  badge.className = `status-badge ${run?.status || ""}`;
  badge.textContent = run ? runNames[run.status] || run.status : "Нет данных";
}

function renderNotices(notices) {
  const box = $("#run-warnings");
  box.hidden = !notices.length;
  box.innerHTML = notices.map((notice) => `<div class="notice-item ${esc(notice.level)}">${esc(notice.text)}</div>`).join("");
}

function renderDistribution(summary) {
  const box = $("#incident-distribution");
  const severities = ["critical", "high", "medium", "low"].filter((name) => summary.by_severity?.[name]);
  const kinds = Object.keys(kindNames).filter((name) => summary.by_kind?.[name]);
  if (!severities.length && !kinds.length) {
    box.hidden = true;
    box.innerHTML = "";
    return;
  }
  box.hidden = false;
  box.innerHTML = [
    severities.length ? `<div class="chip-group"><span class="chip-label">По значимости:</span>${severities.map((name) => `<span class="chip severity ${name}">${severityNames[name]} · ${summary.by_severity[name]}</span>`).join("")}</div>` : "",
    kinds.length ? `<div class="chip-group"><span class="chip-label">По типу:</span>${kinds.map((name) => `<span class="chip">${kindShort[name]} · ${summary.by_kind[name]}</span>`).join("")}</div>` : "",
  ].join("");
}

function basisLabel(incident) {
  if (incident.kind === "rule_conflict") return "конфликт правил";
  if (incident.kind === "unknown_anomaly") return incident.anomaly_score == null ? "модель" : `модель, оценка ${incident.anomaly_score.toFixed(3)}`;
  const rules = (incident.rule_ids || []).join(", ");
  return `${incident.kind === "known_with_anomaly" ? "правило и модель" : "правило"}${rules ? `: ${rules}` : ""}`;
}

async function loadIncidents() {
  if (!state.currentDataset) return;
  const params = new URLSearchParams({ dataset_id: state.currentDataset });
  if (state.currentRun?.id) params.set("run_id", state.currentRun.id);
  const incidents = await api(`/api/incidents?${params}`);
  $("#incident-count").textContent = countLabel(incidents.length, "запись", "записи", "записей");
  if (!incidents.length) {
    $("#incidents-body").innerHTML = '<tr><td colspan="6" class="empty-cell">Инциденты не обнаружены.</td></tr>';
    return;
  }
  $("#incidents-body").innerHTML = incidents.map((incident) => `<tr>
    <td class="time-cell">${esc(formatTime(incident.window_start))}</td>
    <td><strong>${esc(incidentTitle(incident))}</strong><small>${esc(kindShort[incident.kind] || incident.kind)}</small></td>
    <td><strong>${esc(incident.service || "—")}</strong><small>${esc(incident.route || "Маршрут не определён")}</small></td>
    <td><span class="severity ${esc(incident.severity)}">${esc(severityNames[incident.severity] || incident.severity)}</span></td>
    <td class="basis">${esc(basisLabel(incident))}${incident.review_required ? '<small>нужна проверка</small>' : ""}</td>
    <td><button class="row-button" type="button" data-incident="${esc(incident.incident_id)}">Подробнее</button></td>
  </tr>`).join("");
}

function renderTemplates(templates) {
  const total = templates.reduce((sum, item) => sum + item.occurrences, 0);
  $("#template-count").textContent = templates.length
    ? `${countLabel(templates.length, "шаблон", "шаблона", "шаблонов")}, ${countLabel(total, "запись", "записи", "записей")}`
    : "";
  if (!templates.length) {
    $("#templates-body").innerHTML = '<tr><td colspan="4" class="empty-cell">Шаблоны не построены: в наборе нет сообщений.</td></tr>';
    return;
  }
  $("#templates-body").innerHTML = templates.map((item) => `<tr>
    <td class="mono wrap">${esc(item.pattern)}</td>
    <td>${esc(item.occurrences)}</td>
    <td class="time-cell">${esc(formatTime(item.first_seen))}</td>
    <td><button class="row-button" type="button" data-template="${esc(item.template_id)}">Записи</button></td>
  </tr>`).join("");
}

function describeRules(matches) {
  // Одно правило может сработать в окне несколько раз — показывается с числом срабатываний.
  const counts = new Map();
  for (const match of matches || []) counts.set(match.rule, (counts.get(match.rule) || 0) + 1);
  return counts.size ? [...counts].map(([rule, count]) => `${esc(rule)} ×${count}`).join("<br>") : "—";
}

async function loadProtocol() {
  if (!state.currentRun?.id) return;
  const protocol = await api(`/api/runs/${state.currentRun.id}/protocol`);
  const steps = protocol.steps || [];
  const list = $("#protocol-steps");
  list.hidden = !steps.length;
  list.innerHTML = steps.map((step) => `<li><strong>${esc(step.title)}</strong><span class="duration">${esc(step.duration_ms)} мс</span><div class="summary">${esc(describeSummary(step.summary || {}))}</div></li>`).join("");
  const windows = protocol.windows || [];
  $("#protocol-body").innerHTML = windows.length ? windows.map((window) => `<tr>
    <td class="time-cell">${esc(formatTime(window.window_start))}</td>
    <td>${esc(window.features.n_req)}</td>
    <td>${percent(window.features.r_4xx)}</td>
    <td>${percent(window.features.r_5xx)}</td>
    <td>${esc(Math.round(window.features.q_095_duration_ms))}</td>
    <td class="basis">${describeRules(window.rule_matches)}</td>
    <td>${window.model?.score != null ? `${window.model.score.toFixed(3)} · ${esc(modelStatusNames[window.model.status] || window.model.status)}` : esc(window.model ? (modelStatusNames[window.model.status] || window.model.status) : "не применялась")}</td>
    <td>${esc(window.decision.kind ? (kindShort[window.decision.kind] || window.decision.kind) : (reasonNames[window.decision.reason] || "—"))}</td>
  </tr>`).join("") : '<tr><td colspan="8" class="empty-cell">Протокол по окнам отсутствует: анализ ещё не выполнен.</td></tr>';
}

const stepStatuses = { completed: "выполнено", unavailable: "модель недоступна", not_requested: "модель не запрашивалась" };

function describeSummary(summary) {
  const parts = [];
  for (const [key, value] of Object.entries(summary)) {
    if (key === "by_rule" || key === "by_kind") {
      const entries = Object.entries(value || {});
      if (entries.length) {
        const names = entries.map(([name, count]) => `${key === "by_kind" ? (kindShort[name] || name) : name} — ${count}`);
        parts.push(`${key === "by_rule" ? "по правилам" : "по типам"}: ${names.join(", ")}`);
      }
    } else if (value === "completed") {
      continue;
    } else if (key === "status") {
      parts.push(stepStatuses[value] || value);
    } else if (value !== null && value !== undefined && value !== "") {
      parts.push(`${stepKeys[key] || key}: ${value}`);
    }
  }
  return parts.join(" · ");
}

function resetSearchView() {
  state.search.active = false;
  state.search.templateId = null;
  state.search.offset = 0;
  $("#search-summary").hidden = true;
  $("#search-page").textContent = "";
  $("#events-body").innerHTML = '<tr><td colspan="5" class="empty-cell">Задайте условия и нажмите «Найти».</td></tr>';
  $("#search-prev").disabled = true;
  $("#search-next").disabled = true;
}

async function openIncident(id) {
  const incident = await api(`/api/incidents/${id}`);
  const features = incident.features || {};
  const facts = [
    ["Интервал", `${formatTime(incident.window_start)} — ${formatTime(incident.window_end)}`],
    ["Сервис", incident.service || "—"],
    ["Маршрут", incident.route || "—"],
    ["Запросов в окне", features.n_req ?? "—"],
    ["Затронуто запросов", incident.affected_requests ?? "—"],
    ["Повторов признака ошибки", incident.rule_matches || "—"],
    ["4xx / 5xx", `${percent(features.r_4xx)} / ${percent(features.r_5xx)}`],
    ["95-й перцентиль длительности", `${Math.round(features.q_095_duration_ms ?? 0)} мс`],
  ];
  const rules = (incident.rules || []).map((rule) => `<li>${esc(rule.then.title || rule.then.hypothesis || rule.key)} <span class="muted">(${esc(rule.key)})</span></li>`).join("");
  const modelLine = incident.anomaly_score != null
    ? `Оценка аномальности ${incident.anomaly_score.toFixed(3)} при пороге ${incident.anomaly_threshold.toFixed(3)} — окно ${incident.anomaly_score >= incident.anomaly_threshold ? "признано аномальным" : "не выделено моделью"}.`
    : "Модель к этому окну не применялась.";
  const deviations = (incident.deviations || []).map((item) => `<li>${esc(featureNames[item.feature] || item.feature)}: значение ${esc(item.value)} при обычном ${esc(item.baseline_mean)} ± ${esc(item.baseline_std)}</li>`).join("");
  const evidence = (incident.evidence || []).map((item) => {
    const event = item.event || {};
    const request = event.request || {};
    const caption = `${event.source?.service || "—"} · ${formatTime(event.observed_at)} · ${roleNames[item.role] || item.role}`;
    const meta = `${request.method || ""} ${request.route || ""}${request.status ? ` → ${request.status}` : ""}${request.duration_ms != null ? ` · ${request.duration_ms} мс` : ""}${request.request_id ? ` · запрос ${request.request_id}` : ""}`;
    return `<details class="evidence-item"><summary>${esc(caption)}${meta.trim() ? ` <span class="muted">${esc(meta)}</span>` : ""}</summary><pre>${esc(item.excerpt)}</pre></details>`;
  }).join("") || '<p class="muted">Нет связанных записей.</p>';
  const hypotheses = (incident.hypotheses || []).map((item) => `<div class="hypothesis-item"><strong>${esc(hypothesisTitle(item))}</strong><span class="muted">${esc(severityNames[item.severity] || item.severity)} · ${esc((item.rules || []).join(", "))}</span></div>`).join("");
  const assumption = incident.kind === "unknown_anomaly"
    ? '<p>Причина не установлена: отклонение нашла статистическая модель, а правило базы знаний для него не составлено.</p>'
    : (hypotheses || `<p>${esc(incidentTitle(incident))}</p>`);
  const review = incident.kind === "rule_conflict"
    ? `<button class="button secondary full" id="review-button" type="button">${incident.reviewed_at ? "Проверено — снять отметку" : "Отметить как проверенное"}</button>`
    : "";
  $("#incident-detail").innerHTML = `
    <div class="detail-heading">
      <span class="severity ${esc(incident.severity)}">${esc(severityNames[incident.severity] || incident.severity)}</span>
      <h3>${esc(incidentTitle(incident))}</h3>
      <p class="muted">${esc(kindNames[incident.kind] || incident.kind)}</p>
      ${incident.review_required ? '<p class="review-flag">Требуется ручная проверка: однозначный вывод невозможен.</p>' : ""}
    </div>
    <section class="detail-section"><h4>Наблюдаемые факты</h4><dl class="fact-list">${facts.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`).join("")}</dl></section>
    <section class="detail-section"><h4>Результат автоматического анализа</h4>
      <dl class="fact-list">
        <dt>Основание</dt><dd>${esc(confidenceNames[incident.confidence] || incident.confidence)}</dd>
        <dt>Правила базы знаний</dt><dd>${rules ? `<ul class="deviation-list">${rules}</ul>` : "не сработали"}</dd>
        <dt>Модель</dt><dd>${esc(modelLine)}</dd>
        ${deviations ? `<dt>Отклонившиеся признаки</dt><dd><ul class="deviation-list">${deviations}</ul></dd>` : ""}
      </dl>
    </section>
    <section class="detail-section"><h4>Диагностическое предположение</h4>${assumption}<p>${esc(recommendationText(incident))}</p>${review}</section>
    <section class="detail-section"><h4>Исходные записи — доказательства · ${(incident.evidence || []).length}</h4>${evidence}</section>
    ${(incident.warnings || []).length ? `<section class="detail-section"><div class="notice-box">${incident.warnings.map((warning) => `<div class="notice-item warning">${esc(warning)}</div>`).join("")}</div></section>` : ""}`;
  const reviewButton = $("#review-button");
  if (reviewButton) reviewButton.addEventListener("click", async () => {
    reviewButton.disabled = true;
    try {
      await api(`/api/incidents/${incident.incident_id}/review`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reviewed: !incident.reviewed_at }) });
      toast("Результат проверки сохранён");
      await loadDataset(state.currentDataset, state.currentRun?.id);
      await openIncident(incident.incident_id);
    } catch (error) {
      reviewButton.disabled = false;
      toast(error.message, true);
    }
  });
  if (!$("#incident-dialog").open) $("#incident-dialog").showModal();
}

async function pollRun(runId) {
  for (let attempt = 0; attempt < 240; attempt++) {
    const run = await api(`/api/runs/${runId}`);
    state.currentRun = run;
    renderRunStatus(run);
    if (run.status === "completed") {
      await refreshDatasets();
      await refreshModels();
      await loadDataset(run.dataset_id, run.id);
      toast(`Анализ завершён: ${countLabel(run.stats.incidents ?? 0, "инцидент", "инцидента", "инцидентов")}`);
      return;
    }
    if (run.status === "failed") {
      await loadDataset(run.dataset_id, run.id);
      throw new Error(friendlyError(run.error || "Ошибка анализа"));
    }
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw new Error("Превышено время ожидания анализа");
}

function searchQuery() {
  const search = state.search;
  const params = new URLSearchParams({ dataset_id: state.currentDataset });
  if ($("#search-from").value) params.set("time_from", new Date($("#search-from").value).toISOString());
  if ($("#search-to").value) params.set("time_to", new Date($("#search-to").value).toISOString());
  if ($("#search-source").value) params.set("source_type", $("#search-source").value);
  if ($("#search-status").value) params.set("status", $("#search-status").value);
  if ($("#search-severity").value) params.set("severity", $("#search-severity").value);
  if ($("#search-request").value.trim()) params.set("request_id", $("#search-request").value.trim());
  if ($("#search-q").value.trim()) params.set("q", $("#search-q").value.trim());
  if (search.templateId) params.set("template_id", search.templateId);
  return params;
}

async function runSearch(reset = false) {
  if (!state.currentDataset) return;
  if (reset) state.search.offset = 0;
  state.search.active = true;
  const query = searchQuery();
  const page = new URLSearchParams(query);
  page.set("limit", state.search.limit);
  page.set("offset", state.search.offset);
  const [events, counted] = await Promise.all([api(`/api/events?${page}`), api(`/api/events/count?${query}`)]);
  state.search.total = counted.count;
  const from = state.search.total ? state.search.offset + 1 : 0;
  const to = Math.min(state.search.offset + events.length, state.search.total);
  const scope = state.search.templateId ? "по выбранному шаблону" : "по заданным условиям";
  $("#search-summary").hidden = false;
  $("#search-summary").innerHTML = `Найдено ${countLabel(state.search.total, "запись", "записи", "записей")} ${scope}; показаны ${from}–${to}.` + (state.search.templateId ? ' <button class="row-button" type="button" id="search-clear-template">показать все записи</button>' : "");
  $("#search-page").textContent = `Записи ${from}–${to} из ${state.search.total}`;
  $("#search-prev").disabled = state.search.offset <= 0;
  $("#search-next").disabled = to >= state.search.total;
  if (!events.length) {
    $("#events-body").innerHTML = '<tr><td colspan="5" class="empty-cell">Записи по заданным условиям не найдены.</td></tr>';
  } else {
    $("#events-body").innerHTML = events.map((event) => `<tr>
      <td class="time-cell">${esc(formatTime(event.observed_at))}</td>
      <td>${esc(sourceNames[event.source?.type] || event.source?.type || "—")}<small>${esc(event.source?.service || "")}</small></td>
      <td>${esc(event.severity || "—")}</td>
      <td class="wrap">${esc(event.request?.method || "")} ${esc(event.request?.route || event.request?.original_uri || "—")}${event.request?.status ? ` <span class="muted">→ ${esc(event.request.status)}</span>` : ""}</td>
      <td class="wrap">${esc(truncate(event.message || event.raw, 160))}</td>
    </tr>`).join("");
  }
  const clear = $("#search-clear-template");
  if (clear) clear.addEventListener("click", async () => {
    state.search.templateId = null;
    await runSearch(true);
  });
}

$("#demo-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  busy(button, true);
  try {
    const result = await api("/api/demo", { method: "POST" });
    state.currentDataset = result.dataset.id;
    state.currentRun = result.run;
    await refreshDatasets();
    await refreshModels();
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
  const formElement = event.currentTarget;
  const button = formElement.querySelector("button[type=submit]");
  busy(button, true);
  try {
    const form = new FormData(formElement);
    form.set("service", form.get("service")?.trim() || "unknown");
    form.set("analyze", "true");
    const result = await api("/api/datasets", { method: "POST", body: form });
    state.currentDataset = result.dataset.id;
    state.currentRun = result.run;
    await refreshDatasets();
    await loadDataset(result.dataset.id, result.run.id);
    await pollRun(result.run.id);
    formElement.reset();
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(button, false);
  }
});

async function runAnalysis(modelId) {
  if (!state.currentDataset) return;
  const run = await api("/api/analysis", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ dataset_id: state.currentDataset, ...(modelId ? { model_id: modelId } : {}) }),
  });
  state.currentRun = run;
  renderRunStatus(run);
  await pollRun(run.id);
}

$("#dataset-select").addEventListener("change", async (event) => {
  $("#incident-dialog").close();
  resetSearchView();
  try {
    await loadDataset(event.target.value);
  } catch (error) {
    toast(error.message, true);
  }
});

$("#delete-dataset-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  const dataset = state.datasets.find((item) => item.id === state.currentDataset);
  if (!dataset) return;
  if (!confirm(`Удалить набор «${dataset.name}» вместе с событиями, прогонами и инцидентами?`)) return;
  busy(button, true);
  try {
    await api(`/api/datasets/${dataset.id}`, { method: "DELETE" });
    toast(`Набор «${dataset.name}» удалён`);
    state.currentDataset = null;
    state.currentRun = null;
    await refreshDatasets();
    if (state.datasets.length) await loadDataset(state.datasets[0].id);
    else resetResultsView();
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(button, false);
  }
});

$("#purge-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  if (!state.datasets.length) {
    toast("Реестр уже пуст");
    return;
  }
  if (!confirm("Удалить ВСЕ наборы данных, события и инциденты? Правила и модели сохранятся.")) return;
  if (!confirm("Действие необратимо. Точно очистить весь реестр журналов?")) return;
  busy(button, true);
  try {
    const result = await api("/api/maintenance/purge", { method: "POST" });
    toast(`Удалено наборов: ${result.deleted.datasets}, инцидентов: ${result.deleted.incidents}`);
    state.currentDataset = null;
    state.currentRun = null;
    await refreshDatasets();
    resetResultsView();
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(button, false);
  }
});

$("#train-model-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  const dataset = state.datasets.find((item) => item.id === state.currentDataset);
  if (!dataset) return;
  if (!confirm(`Обучить модель на наборе «${dataset.name}»? Подойдёт только «тихий» период без инцидентов.`)) return;
  busy(button, true);
  try {
    const model = await api("/api/models/train", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dataset_id: dataset.id }),
    });
    state.currentModel = model.id;
    toast(`Модель обучена: ${countLabel(model.training_summary.windows, "окно", "окна", "окнов")} штатного периода`);
    updateActionButtons();
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(button, false);
  }
});

$("#analyze-model-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  if (!state.currentDataset || !state.currentModel) return;
  busy(button, true);
  try {
    await runAnalysis(state.currentModel);
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(button, false);
  }
});

$("#rules-only-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  if (!state.currentDataset) return;
  busy(button, true);
  try {
    await runAnalysis(null);
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(button, false);
  }
});

$("#search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  state.search.templateId = null;
  const button = event.currentTarget.querySelector("button[type=submit]");
  busy(button, true);
  try {
    await runSearch(true);
  } catch (error) {
    toast(error.message, true);
  } finally {
    busy(button, false);
  }
});

$("#search-reset").addEventListener("click", async () => {
  $("#search-form").reset();
  state.search.templateId = null;
  await runSearch(true).catch((error) => toast(error.message, true));
});

$("#search-prev").addEventListener("click", async () => {
  state.search.offset = Math.max(0, state.search.offset - state.search.limit);
  await runSearch().catch((error) => toast(error.message, true));
});

$("#search-next").addEventListener("click", async () => {
  state.search.offset += state.search.limit;
  await runSearch().catch((error) => toast(error.message, true));
});

$("#incidents-body").addEventListener("click", (event) => {
  const button = event.target.closest("[data-incident]");
  if (button) openIncident(button.dataset.incident).catch((error) => toast(error.message, true));
});

$("#templates-body").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-template]");
  if (!button) return;
  state.search.templateId = button.dataset.template;
  document.querySelector('[aria-labelledby="search-title"]').scrollIntoView({ behavior: "smooth", block: "start" });
  await runSearch(true).catch((error) => toast(error.message, true));
});

$("#close-incident").addEventListener("click", () => $("#incident-dialog").close());
$("#incident-dialog").addEventListener("click", (event) => {
  if (event.target === event.currentTarget) event.currentTarget.close();
});

(async function init() {
  try {
    await refreshDatasets();
    await refreshModels();
    if (state.datasets.length) await loadDataset(state.datasets[0].id);
  } catch (error) {
    toast(error.message, true);
  }
})();
