"""Real PostgreSQL row-lock coverage for summary publication."""

from typing import Any

import pytest
from psycopg.errors import LockNotAvailable
from sqlalchemy import Engine, delete, event, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from attacksurf.infra.db.models import Asset, Org, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import summary
from tests.fakes import FakeLLMProvider
from tests.integration.services.test_summary_jobs import (
    _completed_scan,
    _job,
    _reply,
    _settings,
    _use_provider,
)


@pytest.mark.parametrize("check_scan_start_lock_order", [False, True])
def test_summary_publication_waits_for_the_root_lock(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch, check_scan_start_lock_order: bool
) -> None:
    # Separate connections need committed fixtures, not db_session's outer transaction.
    with Session(db_engine) as setup:
        scan = _completed_scan(setup)
        job = _job(setup, scan)
        org_id, root_id, scan_id, job_id = scan.org_id, scan.root_asset_id, scan.id, job.id
    # No tag changes: an incidental asset UPDATE must not make this test pass.
    _use_provider(monkeypatch, FakeLLMProvider(_reply(key_risks=[], notable_assets=[])))

    try:
        with Session(db_engine) as blocker, db_engine.connect() as connection:
            blocker.scalars(
                scoped(Asset, org_id).where(Asset.id == root_id).with_for_update()
            ).one()
            connection.execute(text("SET lock_timeout = '250ms'"))
            connection.commit()
            org_lock_acquired: list[bool] = []

            def claim_org_before_summary_waits(
                _connection: Any,
                _cursor: Any,
                statement: str,
                _parameters: Any,
                _context: Any,
                _executemany: bool,
            ) -> None:
                if "FROM assets" in statement and "FOR UPDATE" in statement:
                    # start_scan holds root, then locks Org. The summary must not have
                    # autoflushed a usage FK's Org key-share lock before waiting for root.
                    blocker.execute(
                        select(Org.id).where(Org.id == org_id).with_for_update(nowait=True)
                    ).one()
                    org_lock_acquired.append(True)

            if check_scan_start_lock_order:
                event.listen(connection, "before_cursor_execute", claim_org_before_summary_waits)
            try:
                with Session(bind=connection) as worker:
                    with pytest.raises(OperationalError) as error:
                        summary.run_summary(worker, org_id, job_id, _settings(), retry_allowed=True)
                    assert isinstance(error.value.orig, LockNotAvailable)
                    assert error.value.orig.sqlstate == "55P03"
                if check_scan_start_lock_order:
                    assert org_lock_acquired == [True]
            finally:
                if check_scan_start_lock_order:
                    event.remove(
                        connection, "before_cursor_execute", claim_org_before_summary_waits
                    )
                connection.execute(text("RESET lock_timeout"))
                connection.commit()
        with Session(db_engine) as check:
            stored_scan = check.get(Scan, scan_id)
            assert stored_scan is not None
            assert stored_scan.ai_summary is None
    finally:
        with Session(db_engine) as cleanup:
            cleanup.execute(delete(Org).where(Org.id == org_id))
            cleanup.commit()
