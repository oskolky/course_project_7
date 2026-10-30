#!/usr/bin/env python3
"""Генератор синтетических журналов для проверки log-analyzer.

Создаёт два набора рядом с собой:
  baseline/  — 30 минут штатной нагрузки трёх сервисов (обучение Isolation Forest);
  incident/  — 20 минут нагрузки с зашитыми аномалиями (проверка детекции).

Запуск из корня проекта:  python samples/generated/generate_logs.py
Вывод детерминирован (seed фиксирован): повторный запуск даёт те же файлы.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASELINE_START = datetime(2026, 10, 28, 9, 0, 0, tzinfo=timezone.utc)
INCIDENT_START = datetime(2026, 10, 28, 10, 0, 0, tzinfo=timezone.utc)

CLIENTS = [f"10.0.1.{n}" for n in range(11, 60)]
SCANNER = "203.0.113.99"
AGENTS = ["Mozilla/5.0 (X11; Linux x86_64)", "CourseBot/2.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"]
ROUTES = [
    ("/", 15), ("/api/catalog", 25), ("/api/product/", 20), ("/api/cart", 10),
    ("/api/checkout", 10), ("/api/session", 8), ("/static/app.js", 6), ("/static/logo.png", 6),
]
POST_ROUTES = {"/api/cart", "/api/checkout", "/api/session", "/api/pay"}

rng = random.Random(7)
_rid = 0


def next_rid(prefix: str) -> str:
    global _rid
    _rid += 1
    return f"{prefix}-{_rid}"


def access_time(ts: datetime) -> str:
    return ts.strftime("[%d/%b/%Y:%H:%M:%S +0000]")


def nginx_error_time(ts: datetime) -> str:
    return ts.strftime("%Y/%m/%d %H:%M:%S")


def iso_time(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def pick_route() -> str:
    routes = [r for r, _ in ROUTES]
    weights = [w for _, w in ROUTES]
    route = rng.choices(routes, weights=weights, k=1)[0]
    if route == "/api/product/":
        route += str(rng.randint(100, 999))
    return route


def method_for(route: str) -> str:
    return "POST" if route in POST_ROUTES else "GET"


def access_line(ts, client, method, uri, status, duration_ms, rid, agent=None):
    size = rng.randint(140, 180) if status == 404 else rng.randint(240, 5200)
    agent = agent or rng.choice(AGENTS)
    body = "-" if status in (204, 304) else size
    return (f'{client} - - {access_time(ts)} "{method} {uri} HTTP/1.1" {status} {body} '
            f'"-" "{agent}" {duration_ms / 1000:.3f} {max(duration_ms / 1000 * 0.95, 0.001):.3f} {rid}')


def app_event(ts, service, host, rid, status, duration_ms, message, severity="info"):
    return json.dumps({
        "observed_at": iso_time(ts),
        "source": {"type": "application_json", "service": service, "host": host},
        "severity": severity,
        "request": {"request_id": rid, "trace_id": None, "method": "POST", "status": status, "duration_ms": duration_ms},
        "message": message,
    }, ensure_ascii=False)


def nginx_timeout_line(ts, conn, client, method, uri, rid):
    return (f"{nginx_error_time(ts)} [error] 42#42: *{conn} upstream timed out (110: Connection timed out) "
            f"while reading response header from upstream, client: {client}, server: shop.local, "
            f'request: "{method} {uri} HTTP/1.1", upstream: "http://127.0.0.1:9000{uri}", request_id={rid}')


def nginx_refused_line(ts, conn, client, method, uri, rid):
    return (f"{nginx_error_time(ts)} [error] 55#55: *{conn} connect() failed (111: Connection refused) "
            f"while connecting to upstream, client: {client}, server: pay.local, "
            f'request: "{method} {uri} HTTP/1.1", upstream: "http://127.0.0.1:9100{uri}", request_id={rid}')


def base_request(start: datetime, minute: int):
    ts = start + timedelta(minutes=minute, seconds=rng.randint(0, 59))
    route = pick_route()
    method = method_for(route)
    roll = rng.random()
    if roll < 0.945:
        status = 200
    elif roll < 0.965:
        status = 301 if route == "/" else 204
    elif roll < 0.985:
        status = 404
    else:
        status = 500
    duration = max(5.0, rng.lognormvariate(3.8, 0.35))
    return ts, rng.choice(CLIENTS), method, route, status, round(duration, 1)


def write_sorted(path: Path, rows: list[tuple[datetime, str]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [line for _, line in sorted(rows, key=lambda pair: pair[0])]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def gen_baseline() -> dict[str, int]:
    access, auth, checkout = [], [], []
    for minute in range(30):
        for _ in range(rng.randint(11, 16)):
            ts, client, method, route, status, duration = base_request(BASELINE_START, minute)
            rid = next_rid("req")
            access.append((ts, access_line(ts, client, method, route, status, duration, rid)))
            if route == "/api/session" and method == "POST" and status == 200:
                auth.append((ts, app_event(ts, "auth-api", "web-01", rid, 204, duration, "session issued")))
            if route == "/api/checkout" and method == "POST":
                checkout.append((ts, app_event(ts, "checkout-api", "web-02", rid, status, duration,
                                               f"checkout completed order={rng.randint(10000, 99999)}")))
    return {
        "baseline/access.log": write_sorted(ROOT / "baseline" / "access.log", access),
        "baseline/auth.jsonl": write_sorted(ROOT / "baseline" / "auth.jsonl", auth),
        "baseline/checkout.jsonl": write_sorted(ROOT / "baseline" / "checkout.jsonl", checkout),
    }


def gen_incident() -> dict[str, int]:
    access, nginx_err, auth, checkout, payment_err = [], [], [], [], []

    # фоновый трафик
    for minute in range(20):
        for _ in range(rng.randint(10, 14)):
            ts, client, method, route, status, duration = base_request(INCIDENT_START, minute)
            rid = next_rid("req")
            access.append((ts, access_line(ts, client, method, route, status, duration, rid)))

    # 10:05 — всплеск 401 на /api/session: неверный issuer токена
    for i in range(7):
        ts = INCIDENT_START + timedelta(minutes=5, seconds=10 + i * 7)
        rid = f"auth-{i}"
        client = rng.choice(CLIENTS)
        access.append((ts, access_line(ts, client, "POST", "/api/session", 401, 36.0, rid)))
        auth.append((ts, app_event(ts, "auth-api", "web-01", rid, 401, 36.0,
                                   f"token rejected: unexpected issuer token_id={3100 + i}", severity="warn")))

    # 10:07 — повреждённая JSON-строка (проверка диагностики ingestion)
    broken_ts = INCIDENT_START + timedelta(minutes=7, seconds=12)
    checkout.append((broken_ts, '{"observed_at": "2026-10-28T10:07:12.000000Z", '
                                 '"source": {"service": "checkout-api"}, "message": '))

    # 10:09 — просадка скорости на /api/catalog (модель, без правила)
    for i in range(8):
        ts = INCIDENT_START + timedelta(minutes=9, seconds=5 + i * 6)
        rid = f"slow-{i}"
        access.append((ts, access_line(ts, rng.choice(CLIENTS), "GET", "/api/catalog", 200,
                                       float(rng.randint(1100, 1500)), rid)))

    # 10:12 — тайм-ауты upstream на /api/checkout (правило UPSTREAM_TIMEOUT)
    for i in range(6):
        ts = INCIDENT_START + timedelta(minutes=12, seconds=8 + i * 6)
        rid = f"up-{i}"
        client = rng.choice(CLIENTS)
        access.append((ts, access_line(ts, client, "GET", "/api/checkout", 504, 3002.0, rid)))
        nginx_err.append((ts, nginx_timeout_line(ts, 100 + i, client, "GET", "/api/checkout", rid)))
        checkout.append((ts, app_event(ts, "checkout-api", "web-02", rid, 504, 3002.0,
                                       "checkout pipeline stalled: inventory lock held for 3000ms",
                                       severity="warn")))

    # 10:15 — платёжный шлюз отказывает: 502 (модель, правила нет)
    for i in range(4):
        ts = INCIDENT_START + timedelta(minutes=15, seconds=33 + i * 9)
        rid = f"pay-{i}"
        client = rng.choice(CLIENTS)
        access.append((ts, access_line(ts, client, "POST", "/api/pay", 502, 52.0, rid)))
        payment_err.append((ts, nginx_refused_line(ts, 200 + i, client, "POST", "/api/pay", rid)))

    # 10:18 — сканер статики: массовые 404 с одного адреса (модель, правила нет)
    for i in range(35):
        ts = INCIDENT_START + timedelta(minutes=18, seconds=3 + i)
        rid = f"scan-{i}"
        access.append((ts, access_line(ts, SCANNER, "GET", f"/static/missing-{i}.css", 404, 4.0, rid,
                                       agent="Nikto/2.1.6")))

    return {
        "incident/access.log": write_sorted(ROOT / "incident" / "access.log", access),
        "incident/nginx_error.log": write_sorted(ROOT / "incident" / "nginx_error.log", nginx_err),
        "incident/auth.jsonl": write_sorted(ROOT / "incident" / "auth.jsonl", auth),
        "incident/checkout.jsonl": write_sorted(ROOT / "incident" / "checkout.jsonl", checkout),
        "incident/payment_error.log": write_sorted(ROOT / "incident" / "payment_error.log", payment_err),
    }


def main():
    counts = gen_baseline()
    counts.update(gen_incident())
    for name, count in sorted(counts.items()):
        print(f"{name}: {count} строк")
    print("готово: samples/generated/{baseline,incident}/")


if __name__ == "__main__":
    main()
