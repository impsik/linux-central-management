import asyncio
from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


@pytest.mark.parametrize('new_status,future', [('running', False), ('done', False), ('scheduled', True)])
def test_dispatch_refreshes_stale_worker_before_claiming(tmp_path, new_status, future):
    from app.models import Base, CronJob, CronJobRun
    from app.services.cronjobs import _dispatch_one
    engine = create_engine(f'sqlite:///{tmp_path / "cron.db"}')
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as first, Session(engine) as other:
            job = CronJob(user_id=uuid4(), action='dist-upgrade', status='scheduled',
                          run_at=datetime.now(timezone.utc) - timedelta(minutes=1), selector={'agent_ids': ['node']})
            first.add(job)
            first.commit()
            # Tick has already loaded the old scheduled state in its identity map.
            stale = first.get(CronJob, job.id)
            changed = other.get(CronJob, job.id)
            changed.status = new_status
            if future:
                changed.run_at = datetime.now(timezone.utc) + timedelta(days=1)
            other.commit()
            asyncio.run(_dispatch_one(first, stale))
            assert first.scalars(select(CronJobRun)).all() == []
            first.refresh(stale)
            assert stale.status == new_status
    finally:
        engine.dispose()
