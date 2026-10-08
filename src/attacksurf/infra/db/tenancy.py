"""Tenant-scoped queries: the only way services should read tenant-owned rows (ADR 0006)."""

from uuid import UUID

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from attacksurf.infra.db.base import TenantScoped


def scoped[T: TenantScoped](model: type[T], org_id: UUID) -> Select[T]:
    """`SELECT model WHERE org_id = :org_id`; add further filters with `.where(...)`."""
    return select(model).where(model.org_id == org_id)


def get_scoped[T: TenantScoped](
    session: Session, model: type[T], id_: UUID, org_id: UUID
) -> T | None:
    """Row by id, or None if it doesn't exist *or belongs to another org* (no existence leak)."""
    return session.scalars(scoped(model, org_id).where(model.id == id_)).one_or_none()
