# Сгенерированный сценарий для проверки log-analyzer

Синтетические журналы трёх сервисов (`shop-web` — NGINX, `auth-api`, `checkout-api`, платёжный шлюз).
Файлы создаёт скрипт `generate_logs.py` (детерминирован, seed зафиксирован):

```bash
python samples/generated/generate_logs.py
```

## Состав

| Набор | Файл | Что внутри |
|---|---|---|
| `baseline/` | `access.log` (394 строки) | 30 минут штатного трафика, 09:00–09:30 |
| | `auth.jsonl` (28) | события auth-api, связаны с access по `request_id` |
| | `checkout.jsonl` (40) | события checkout-api, связаны по `request_id` |
| `incident/` | `access.log` (306) | 20 минут трафика, 10:00–10:20, с аномалиями |
| | `nginx_error.log` (6) | «upstream timed out», `request_id=up-N` |
| | `auth.jsonl` (7) | «token rejected: unexpected issuer», `request_id=auth-N` |
| | `checkout.jsonl` (7) | «checkout pipeline stalled» + одна битая JSON-строка |
| | `payment_error.log` (4) | «connect() failed (111: Connection refused)», `request_id=pay-N` |

## Зашитые аномалии (инцидентный день)

| Время | Событие | Ожидание |
|---|---|---|
| 10:05 | 7× POST /api/session → 401, «unexpected issuer» | правило `AUTH_ISSUER_MISMATCH` (`known`), модель подтверждает |
| 10:07 | повреждённая JSON-строка в checkout.jsonl | запись в `issues`, обработка не прерывается |
| 10:09 | 8× GET /api/catalog, 200, но ~1.2–1.5 с | правила нет — только модель (медленная просадка) |
| 10:12 | 6× GET /api/checkout → 504, «upstream timed out» | правило `UPSTREAM_TIMEOUT` (`known`), модель подтверждает |
| 10:15 | 4× POST /api/pay → 502, «Connection refused» | правила нет — только модель |
| 10:18 | 35× 404 /static/missing-N.css с одного IP | правила нет — только модель (сканер) |

## Как прогнать

```bash
# 1. baseline: загрузка + обучение модели
BASE_ID=$(curl -s -X POST http://localhost:3000/api/datasets -F "name=baseline" -F "service=shop" \
  -F "files=@samples/generated/baseline/access.log" -F "files=@samples/generated/baseline/auth.jsonl" \
  -F "files=@samples/generated/baseline/checkout.jsonl" | python3 -c "import json,sys; print(json.load(sys.stdin)['dataset']['id'])")
curl -s -X POST http://localhost:3000/api/models/train \
  -H 'Content-Type: application/json' -d "{\"dataset_id\": \"$BASE_ID\"}"

# 2. инцидентный день: загрузка и анализ с моделью
INC_ID=$(curl -s -X POST http://localhost:3000/api/datasets -F "name=incident" -F "service=shop" \
  -F "files=@samples/generated/incident/access.log" -F "files=@samples/generated/incident/nginx_error.log" \
  -F "files=@samples/generated/incident/auth.jsonl" -F "files=@samples/generated/incident/checkout.jsonl" \
  -F "files=@samples/generated/incident/payment_error.log" | python3 -c "import json,sys; print(json.load(sys.stdin)['dataset']['id'])")
curl -s -X POST http://localhost:3000/api/analysis -H 'Content-Type: application/json' \
  -d "{\"dataset_id\": \"$INC_ID\", \"model_id\": \"iforest_<id из шага 1>\"}"
```

То же самое в UI: выбрать все файлы папки одной загрузкой, затем «Запустить демо» не нужно —
загрузка по умолчанию сразу запускает анализ (`analyze=true`), повторный запуск с моделью —
кнопкой повторного анализа или `POST /api/analysis`.

## Фактический результат прогона (проверено)

- ingestion: 330 строк прочитано, 329 нормализовано, 1 отклонена (битая JSON-строка зафиксирована в issues), 20/20 окон ready;
- правила: 13 срабатываний (`AUTH_ISSUER_MISMATCH` в 10:05, `UPSTREAM_TIMEOUT` в 10:12), корреляция собрала доказательства из access + error + application по `request_id` (27 событий в инциденте 10:05, 32 в 10:12);
- модель дополнительно пометила окна 10:09 (q95 = 1267 мс), 10:15 (r5xx = 0.21), 10:18 (r4xx = 0.73) как `unknown_anomaly`;
- часть «тихих» окон тоже получила `unknown_anomaly` со score ~0.96–0.99 — это следствие `contamination=0.08` у Isolation Forest: ~8 % окон помечаются по умолчанию и отправляются на ручную проверку, а не игнорируются.

## Куда развивать сценарий

- добавить правило под `connect() failed ... Connection refused` + 502 (через `POST /api/rules`), чтобы платёжный шлюз давал `known`-инциденты;
- обучить модель с меньшим `contamination` (например, 0.03), чтобы снизить шум;
- расширить `generate_logs.py` новыми сервисами и паттернами — скрипт идемпотентен.
