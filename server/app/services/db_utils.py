from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy.orm import Session


@contextmanager
def transaction(db: Session):
    """Simple transaction helper.

    Keeps the MVP-style synchronous SQLAlchemy usage, but centralizes commit/rollback.
    """
    try:
        yield
        db.commit()
    except Exception:
        db.rollback()
        raise
