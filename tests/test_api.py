from __future__ import annotations


def test_api_upload_analysis_and_masking(client):
    line = '10.0.0.25 - - [27/Oct/2026:10:00:00 +0000] "GET /api/item/42?token=secret-value HTTP/1.1" 200 10 "-" "agent" 0.025 - req-1'
    response = client.post(
        "/api/datasets", data={"adapter": "nginx", "service": "web", "analyze": "false"},
        files={"files": ("access.log", line, "text/plain")},
    )
    assert response.status_code == 202
    dataset = response.json()["dataset"]
    events = client.get("/api/events", params={"dataset_id": dataset["id"]}).json()
    assert events[0]["request"]["route"] == "/api/item/{id}"
    assert events[0]["raw"].startswith("10.0.0.<masked>")
    assert "secret-value" not in events[0]["raw"]
    run = client.post("/api/analysis", json={"dataset_id": dataset["id"]})
    assert run.status_code == 202
    assert client.get(f"/api/runs/{run.json()['id']}").json()["status"] == "completed"


def test_api_demo_and_incident_evidence(client):
    response = client.post("/api/demo")
    assert response.status_code == 202
    payload = response.json()
    run = client.get(f"/api/runs/{payload['run']['id']}").json()
    assert run["status"] == "completed"
    assert run["stats"]["evidence_coverage"] == 100.0
    incidents = client.get("/api/incidents", params={"dataset_id": payload["dataset"]["id"]}).json()
    assert {item["hypothesis"] for item in incidents} == {"authentication_issuer_mismatch", "upstream_timeout"}
    detail = client.get(f"/api/incidents/{incidents[0]['incident_id']}").json()
    assert detail["evidence"]
    assert detail["rules"]
    assert client.get("/api/overview", params={"dataset_id": payload["dataset"]["id"]}).status_code == 200


def test_rule_versions_are_immutable(client):
    yaml_text = """
id: TEST_RULE
version: 1
scope: group
when:
  status_in: [500]
then:
  hypothesis: test_cause
  severity: low
  recommendation: test
  evidence: [status]
"""
    assert client.post("/api/rules", json={"yaml_text": yaml_text}).status_code == 201
    duplicate = client.post("/api/rules", json={"yaml_text": yaml_text})
    assert duplicate.status_code == 400
    assert "immutable" in duplicate.json()["detail"]
