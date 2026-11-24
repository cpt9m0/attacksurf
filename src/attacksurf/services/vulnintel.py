"""Vulnerability intelligence sync and product-version matching use cases (#74)."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.ids import uuid7
from attacksurf.domain.vulnintel import (
    CpeRange,
    CveRecord,
    EpssEntry,
    KevEntry,
    ProductVulnerability,
    SyncSummary,
    is_valid_version,
    normalize_cpe_part,
    version_matches_range,
)
from attacksurf.infra.db.models import VulnCpeRange, VulnCve, VulnSyncState
from attacksurf.infra.vulnintel import (
    VulnIntelHttpClient,
    fetch_epss_scores,
    fetch_kev_catalog,
    fetch_nvd_modified,
)

_DB_BATCH_SIZE = 500
_EPSS_MIN_REFRESH_AGE = timedelta(hours=20)


def _upsert_nvd_cves(session: Session, records: list[CveRecord], *, now: datetime) -> None:
    for offset in range(0, len(records), _DB_BATCH_SIZE):
        batch = records[offset : offset + _DB_BATCH_SIZE]
        rows = [
            {
                "cve_id": r.cve_id,
                "description": r.description,
                "published_at": r.published_at,
                "last_modified_at": r.last_modified_at,
                "cvss_v3_score": r.cvss_v3_score,
                "cvss_v3_vector": r.cvss_v3_vector,
                "cvss_v4_score": r.cvss_v4_score,
                "cvss_v4_vector": r.cvss_v4_vector,
                "in_kev": False,
                "created_at": now,
                "updated_at": now,
            }
            for r in batch
        ]
        stmt = pg_insert(VulnCve).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=[VulnCve.cve_id],
            set_={
                "description": stmt.excluded.description,
                "published_at": stmt.excluded.published_at,
                "last_modified_at": stmt.excluded.last_modified_at,
                "cvss_v3_score": stmt.excluded.cvss_v3_score,
                "cvss_v3_vector": stmt.excluded.cvss_v3_vector,
                "cvss_v4_score": stmt.excluded.cvss_v4_score,
                "cvss_v4_vector": stmt.excluded.cvss_v4_vector,
                "updated_at": now,
            },
        )
        session.execute(stmt)


def _replace_cpe_ranges(session: Session, ranges_by_cve: dict[str, list[CpeRange]]) -> int:
    cve_ids = list(ranges_by_cve)
    for offset in range(0, len(cve_ids), _DB_BATCH_SIZE):
        batch_ids = cve_ids[offset : offset + _DB_BATCH_SIZE]
        session.execute(delete(VulnCpeRange).where(VulnCpeRange.cve_id.in_(batch_ids)))

    all_rows = [
        {
            "id": uuid7(),
            "cve_id": r.cve_id,
            "vendor": r.vendor,
            "product": r.product,
            "exact_version": r.exact_version,
            "version_start_including": r.version_start_including,
            "version_start_excluding": r.version_start_excluding,
            "version_end_including": r.version_end_including,
            "version_end_excluding": r.version_end_excluding,
        }
        for cve_ranges in ranges_by_cve.values()
        for r in cve_ranges
    ]
    for offset in range(0, len(all_rows), _DB_BATCH_SIZE):
        session.execute(insert(VulnCpeRange), all_rows[offset : offset + _DB_BATCH_SIZE])
    return len(all_rows)


def _record_sync_state(
    session: Session,
    *,
    source: str,
    now: datetime,
    cursor_timestamp: datetime | None,
    cursor_tag: str | None,
    records_processed: int,
) -> None:
    stmt = pg_insert(VulnSyncState).values(
        source=source,
        last_synced_at=now,
        cursor_timestamp=cursor_timestamp,
        cursor_tag=cursor_tag,
        records_processed=records_processed,
        created_at=now,
        updated_at=now,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[VulnSyncState.source],
        set_={
            "last_synced_at": now,
            "cursor_timestamp": cursor_timestamp,
            "cursor_tag": cursor_tag,
            "records_processed": records_processed,
            "updated_at": now,
        },
    )
    session.execute(stmt)


def sync_nvd(
    session: Session,
    client: VulnIntelHttpClient,
    *,
    now: datetime,
    nvd_api_key: str | None = None,
    initial_lookback_days: int = 30,
) -> tuple[int, int, datetime]:
    """Incrementally ingest NVD CVEs and CPE ranges; building block (does not commit)."""
    state = session.get(VulnSyncState, "nvd")
    if state is not None and state.cursor_timestamp is not None:
        start = state.cursor_timestamp
    else:
        start = now - timedelta(days=initial_lookback_days)

    records, ranges_by_cve = fetch_nvd_modified(client, start=start, end=now, api_key=nvd_api_key)
    if records:
        _upsert_nvd_cves(session, records, now=now)
    range_count = _replace_cpe_ranges(session, ranges_by_cve) if ranges_by_cve else 0

    _record_sync_state(
        session,
        source="nvd",
        now=now,
        cursor_timestamp=now,
        cursor_tag=None,
        records_processed=len(records),
    )
    session.flush()
    return len(records), range_count, now


def _upsert_kev_cves(session: Session, entries: list[KevEntry], *, now: datetime) -> None:
    for offset in range(0, len(entries), _DB_BATCH_SIZE):
        batch = entries[offset : offset + _DB_BATCH_SIZE]
        rows = [
            {
                "cve_id": e.cve_id,
                "description": e.short_description,
                "in_kev": True,
                "kev_date_added": e.date_added,
                "created_at": now,
                "updated_at": now,
            }
            for e in batch
        ]
        stmt = pg_insert(VulnCve).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=[VulnCve.cve_id],
            set_={
                "in_kev": True,
                "kev_date_added": stmt.excluded.kev_date_added,
                "updated_at": now,
            },
        )
        session.execute(stmt)


def sync_kev(
    session: Session,
    client: VulnIntelHttpClient,
    *,
    now: datetime,
) -> tuple[int, str | None]:
    """Sync CISA KEV flags and dates; building block (does not commit)."""
    catalog_version, entries = fetch_kev_catalog(client)
    state = session.get(VulnSyncState, "kev")
    if catalog_version is not None and state is not None and state.cursor_tag == catalog_version:
        _record_sync_state(
            session,
            source="kev",
            now=now,
            cursor_timestamp=state.cursor_timestamp,
            cursor_tag=catalog_version,
            records_processed=0,
        )
        session.flush()
        return 0, catalog_version

    if entries:
        _upsert_kev_cves(session, entries, now=now)

    kev_ids = [entry.cve_id for entry in entries]
    clear_stmt = (
        update(VulnCve)
        .where(VulnCve.in_kev.is_(True))
        .values(in_kev=False, kev_date_added=None, updated_at=now)
    )
    if kev_ids:
        clear_stmt = clear_stmt.where(VulnCve.cve_id.notin_(kev_ids))
    session.execute(clear_stmt)

    _record_sync_state(
        session,
        source="kev",
        now=now,
        cursor_timestamp=now,
        cursor_tag=catalog_version,
        records_processed=len(entries),
    )
    session.flush()
    return len(entries), catalog_version


def _apply_epss_entries(session: Session, entries: list[EpssEntry], *, now: datetime) -> int:
    by_id = {e.cve_id: e for e in entries}
    if not by_id:
        return 0
    rows = session.scalars(select(VulnCve).where(VulnCve.cve_id.in_(list(by_id)))).all()
    for row in rows:
        entry = by_id[row.cve_id]
        row.epss_score = entry.score
        row.epss_percentile = entry.percentile
        row.updated_at = now
    return len(rows)


def sync_epss(
    session: Session,
    client: VulnIntelHttpClient,
    *,
    now: datetime,
    batch_size: int = 100,
) -> tuple[int, str | None]:
    """Sync FIRST EPSS scores for CVEs stored locally; building block (does not commit)."""
    state = session.get(VulnSyncState, "epss")
    last_tag = state.cursor_tag if state is not None else None
    recently_synced = (
        state is not None
        and state.last_synced_at is not None
        and (now - state.last_synced_at) < _EPSS_MIN_REFRESH_AGE
    )

    unscored_ids = list(
        session.scalars(
            select(VulnCve.cve_id).where(VulnCve.epss_score.is_(None)).order_by(VulnCve.cve_id)
        ).all()
    )
    scored_ids = (
        []
        if recently_synced
        else list(
            session.scalars(
                select(VulnCve.cve_id)
                .where(VulnCve.epss_score.is_not(None))
                .order_by(VulnCve.cve_id)
            ).all()
        )
    )

    updated = 0
    latest_model_date: str | None = last_tag

    for offset in range(0, len(unscored_ids), batch_size):
        model_date, entries = fetch_epss_scores(client, unscored_ids[offset : offset + batch_size])
        if model_date is not None:
            latest_model_date = model_date
        updated += _apply_epss_entries(session, entries, now=now)

    for idx, offset in enumerate(range(0, len(scored_ids), batch_size)):
        model_date, entries = fetch_epss_scores(client, scored_ids[offset : offset + batch_size])
        if model_date is not None:
            latest_model_date = model_date
        if idx == 0 and last_tag is not None and model_date == last_tag:
            break
        updated += _apply_epss_entries(session, entries, now=now)

    _record_sync_state(
        session,
        source="epss",
        now=now,
        cursor_timestamp=now if updated > 0 or state is None else state.cursor_timestamp,
        cursor_tag=latest_model_date,
        records_processed=updated,
    )
    session.flush()
    return updated, latest_model_date


def sync_vuln_intel(
    session: Session,
    client: VulnIntelHttpClient,
    *,
    now: datetime | None = None,
    nvd_api_key: str | None = None,
    initial_lookback_days: int = 30,
) -> SyncSummary:
    """Run one NVD + CISA KEV + FIRST EPSS sync cycle and commit once."""
    current = (now or datetime.now(UTC)).astimezone(UTC)
    cves_upserted, ranges_upserted, nvd_cursor = sync_nvd(
        session,
        client,
        now=current,
        nvd_api_key=nvd_api_key,
        initial_lookback_days=initial_lookback_days,
    )
    kev_updated, kev_version = sync_kev(session, client, now=current)
    epss_updated, epss_date = sync_epss(session, client, now=current)
    session.commit()
    return SyncSummary(
        nvd_cves_upserted=cves_upserted,
        nvd_ranges_upserted=ranges_upserted,
        kev_updated=kev_updated,
        epss_updated=epss_updated,
        nvd_cursor=nvd_cursor,
        kev_catalog_version=kev_version,
        epss_model_date=epss_date,
    )


def match_product(
    session: Session, vendor: str, product: str, version: str
) -> tuple[ProductVulnerability, ...]:
    """Return known vulnerabilities matching `(vendor, product, version)`, KEV-first."""
    norm_vendor = normalize_cpe_part(vendor)
    norm_product = normalize_cpe_part(product)
    norm_version = version.strip()
    if not norm_vendor or not norm_product or not is_valid_version(norm_version):
        return ()

    stmt = (
        select(VulnCpeRange, VulnCve)
        .join(VulnCve, VulnCpeRange.cve_id == VulnCve.cve_id)
        .where(VulnCpeRange.vendor == norm_vendor, VulnCpeRange.product == norm_product)
    )
    matched_cves: dict[str, VulnCve] = {}
    for cpe_range, cve in session.execute(stmt):
        if version_matches_range(
            norm_version,
            exact_version=cpe_range.exact_version,
            version_start_including=cpe_range.version_start_including,
            version_start_excluding=cpe_range.version_start_excluding,
            version_end_including=cpe_range.version_end_including,
            version_end_excluding=cpe_range.version_end_excluding,
        ):
            matched_cves[cve.cve_id] = cve

    results = [
        ProductVulnerability(
            cve_id=cve.cve_id,
            description=cve.description,
            published_at=cve.published_at,
            cvss_v3_score=cve.cvss_v3_score,
            cvss_v3_vector=cve.cvss_v3_vector,
            cvss_v4_score=cve.cvss_v4_score,
            cvss_v4_vector=cve.cvss_v4_vector,
            in_kev=cve.in_kev,
            kev_date_added=cve.kev_date_added,
            epss_score=cve.epss_score,
            epss_percentile=cve.epss_percentile,
        )
        for cve in matched_cves.values()
    ]
    results.sort(
        key=lambda v: (
            not v.in_kev,
            -(v.max_cvss if v.max_cvss is not None else -1.0),
            -(v.epss_score if v.epss_score is not None else -1.0),
            v.cve_id,
        )
    )
    return tuple(results)


class DbVulnIntelLookup:
    """Short-lived read-only vulnerability catalog lookup for passive scanners."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def match_product(
        self, vendor: str, product: str, version: str
    ) -> tuple[ProductVulnerability, ...]:
        with self._session_factory() as session:
            return match_product(session, vendor, product, version)
