import asyncio
import threading
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def local_database_config(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")


@pytest.mark.parametrize("cancel", [False, True])
def test_cve_parser_keeps_loop_responsive_and_temp_file_alive(monkeypatch, cancel):
    from app.services import cve_sync

    class Response:
        status = 200

        def __init__(self):
            self.content = self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            seen["download_closed"] = True

        async def iter_chunked(self, size):
            yield b"downloaded-oval"

    class ClientSession(Response):
        def __init__(self, **kwargs):
            pass

        def get(self, url):
            return Response()

    class DB:
        async def commit(self):
            seen["committed"] = True

    release = threading.Event()
    seen = {}

    async def exercise():
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        loop_thread = threading.get_ident()

        def parse(path, codename, result):
            assert seen.get("download_closed"), "HTTP timeout must end before parsing starts"
            seen["path"] = Path(path)
            seen["thread"] = threading.get_ident()
            loop.call_soon_threadsafe(started.set)
            seen["released"] = release.wait(2)
            # The caller must not unlink the file while this worker still owns it.
            seen["content"] = Path(path).read_bytes()
            result["CVE-2026-1234"] = {codename: {"packages": {}}}

        async def upsert(db, result):
            assert threading.get_ident() == loop_thread
            assert "CVE-2026-1234" in result
            assert not seen["path"].exists()

        async def replace(db, codename, result):
            assert codename == "noble"

        monkeypatch.setattr(cve_sync, "SUPPORTED_RELEASES", ["noble"])
        monkeypatch.setattr(cve_sync.aiohttp, "ClientSession", ClientSession)
        monkeypatch.setattr(cve_sync, "parse_oval_bz2_file", parse)
        monkeypatch.setattr(cve_sync, "_upsert_cve_definitions", upsert)
        monkeypatch.setattr(cve_sync, "_replace_release_lookup", replace)
        task = asyncio.create_task(cve_sync.sync_cve_definitions(DB()))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            assert seen["thread"] != loop_thread
            assert seen["path"].exists()
            if cancel:
                # Repeated cancellation must still wait for the thread.
                for _ in range(2):
                    task.cancel()
                    await asyncio.sleep(0)
                    assert not task.done()
                    assert seen["path"].exists()
            release.set()
            if cancel:
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                await task
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert seen["released"] is True
        assert seen["content"] == b"downloaded-oval"
        assert not seen["path"].exists()
        assert seen.get("committed", False) is not cancel

    asyncio.run(exercise())


@pytest.mark.parametrize("cancel", [False, True])
def test_report_worker_owns_session_and_finishes_before_loop_exits(monkeypatch, cancel):
    from app.services import cve_reporting

    release = threading.Event()
    seen = []

    class DB:
        def __init__(self):
            seen.append(("create", threading.get_ident()))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            seen.append(("close", threading.get_ident()))

    async def exercise():
        loop = asyncio.get_running_loop()
        loop_thread = threading.get_ident()
        started = asyncio.Event()
        stop = asyncio.Event()

        def report(db):
            assert isinstance(db, DB)
            seen.append(("report", threading.get_ident()))
            loop.call_soon_threadsafe(started.set)
            assert release.wait(2), "event loop did not release the worker"

        monkeypatch.setattr(cve_reporting, "SessionLocal", DB)
        monkeypatch.setattr(cve_reporting, "run_hourly_report_once", report)
        task = asyncio.create_task(cve_reporting.cve_reporting_loop(stop, interval_s=0))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            assert seen[0][1] != loop_thread
            stop.set()
            if cancel:
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done()
                assert [step for step, _ in seen] == ["create", "report"]
            release.set()
            if cancel:
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                await task
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())
    assert [step for step, _ in seen] == ["create", "report", "close"]
    assert len({thread_id for _, thread_id in seen}) == 1


def test_report_smtp_connection_has_bounded_timeout(monkeypatch):
    from app.services import cve_reporting

    seen = {}

    class SMTP:
        def __init__(self, host, *, timeout):
            seen.update(host=host, timeout=timeout)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def send_message(self, message):
            seen["recipient"] = message["To"]

    monkeypatch.setattr(cve_reporting.smtplib, "SMTP", SMTP)
    cve_reporting.send_report_via_smtp(recipient="test@example.invalid", subject="test", body="test")
    assert seen == {"host": "localhost", "timeout": 10, "recipient": "test@example.invalid"}


def test_severity_lookup_preserves_legacy_json_fallback_without_loading_documents():
    from sqlalchemy import create_engine, insert
    from sqlalchemy.orm import Session
    from app.models import CVEDefinition
    from app.services.cve_reporting import _load_cve_severity_map

    engine = create_engine("sqlite+pysqlite:///:memory:")
    CVEDefinition.__table__.create(engine)
    rows = [
        ("stored", "9.0", {"severity": 7.1}),
        ("numeric", None, {"severity": 8.4}),
        ("textual", "", {"severity": "high"}),
        ("missing", None, {"noble": {"packages": {"package": "large-unused-document"}}}),
    ]
    with engine.begin() as connection:
        connection.execute(insert(CVEDefinition), [
            {"cve_id": cve_id, "severity": severity, "definition_data": data}
            for cve_id, severity, data in rows
        ])
    with Session(engine) as db:
        assert _load_cve_severity_map(db, [row[0] for row in rows]) == {
            "stored": 9.0, "numeric": 8.4, "textual": 8.9,
        }
        assert not db.identity_map
        assert _load_cve_severity_map(db, []) == {}
    engine.dispose()


def test_lookup_replacement_batches_parameters_without_expanding_sql():
    from sqlalchemy import event, insert, select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from app.models import CVEDefinition, CVEPackage
    from app.services.cve_sync import _replace_release_lookup

    async def exercise():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as connection:
            await connection.run_sync(CVEDefinition.__table__.create)
            await connection.run_sync(CVEPackage.__table__.create)
        statements = []

        def capture(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith("INSERT INTO cve_packages"):
                statements.append((len(statement), executemany, len(parameters)))

        factory = async_sessionmaker(engine)
        try:
            async with factory() as db:
                await db.execute(insert(CVEDefinition), [
                    {"cve_id": cve_id, "definition_data": {}}
                    for cve_id in ("CVE-test", "CVE-missing-severity")
                ])
                await db.execute(insert(CVEPackage), [
                    {"cve_id": "CVE-test", "package_name": "old", "release": release, "fixed_version": "1"}
                    for release in ("noble", "jammy")
                ])
                await db.commit()
                event.listen(engine.sync_engine, "before_cursor_execute", capture)
                def packages(start, stop):
                    return {
                        f"package-{index}": {"fixed_version": str(index), "status": "released"}
                        for index in range(start, stop)
                    }

                await _replace_release_lookup(db, "noble", {
                    "CVE-test": {"severity": "8.9", "noble": {"packages": packages(0, 3001)}},
                    "CVE-missing-severity": {"noble": {"packages": packages(3001, 6001)}},
                })
                await db.commit()
                rows = (await db.execute(select(CVEPackage))).scalars().all()
                noble = {row.package_name: row for row in rows if row.release == "noble"}
                assert len(noble) == 6001
                assert "old" not in noble
                assert noble["package-5000"].fixed_version == "5000"
                assert noble["package-0"].severity == "8.9"
                assert noble["package-6000"].severity is None
                assert [(row.package_name, row.fixed_version) for row in rows if row.release == "jammy"] == [("old", "1")]
                assert len({row.id for row in rows}) == len(rows)
            # Bounded SQL text is compiled once per batch, rather than a growing
            # 5000-row VALUES expression tying up the API's event loop.
            assert [count for _, _, count in statements] == [5000, 1001]
            assert all(executemany and sql_length < 1000 for sql_length, executemany, _ in statements)
        finally:
            await engine.dispose()

    asyncio.run(exercise())
