import os

from fastapi.testclient import TestClient

from skoll.web_server import app

client = TestClient(app)


def test_root_returns_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_status_endpoint():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "api_key_configured" in data


def test_analyze_path_invalid():
    response = client.post(
        "/api/analyze/path",
        json={"path": "/ruta/que/no/existe/12345"}
    )
    assert response.status_code == 400
    assert "no existe" in response.json()["detail"]


def test_analyze_url_missing_url():
    response = client.post(
        "/api/analyze/url",
        json={}
    )
    assert response.status_code == 400
    assert "URL vacía" in response.json()["detail"]


def test_chat_message_no_session():
    response = client.post(
        "/api/chat/message",
        json={"session_id": "fake", "message": "hola"}
    )
    assert response.status_code == 400
    assert "no válida" in response.json()["detail"]


def test_chat_message_empty():
    response = client.post(
        "/api/chat/message",
        json={"session_id": "test", "message": ""}
    )
    assert response.status_code == 400


def test_analyze_file_sin_archivo():
    response = client.post("/api/analyze/file")
    assert response.status_code == 422


def test_scan_path_invalid():
    response = client.post(
        "/api/scan",
        json={"path": "/ruta/inexistente/abc123", "tool": "bandit"}
    )
    assert response.status_code == 400
    assert "no existe" in response.json()["detail"]


def test_analyze_path_existente():
    response = client.post(
        "/api/analyze/path",
        json={"path": "pyproject.toml"}
    )
    # Si no hay API key, debe fallar con 500
    if not os.getenv("GEMINI_API_KEY"):
        assert response.status_code == 500
        assert "API Key" in response.json()["detail"]
    else:
        assert response.status_code == 200
