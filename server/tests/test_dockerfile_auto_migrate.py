from pathlib import Path


def test_server_dockerfile_runs_alembic_before_uvicorn():
    dockerfile = Path(__file__).resolve().parents[1] / 'Dockerfile'
    src = dockerfile.read_text()

    assert 'alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000' in src
    assert 'CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]' not in src
