"""Query-string parsing shared by the asset pages and `/api/v1/assets`."""

from uuid import UUID

from flask import abort
from werkzeug.datastructures import MultiDict

from attacksurf.domain.assets import MAX_HOSTNAME_LENGTH, AssetType
from attacksurf.services.asset_views import AssetFilter, AssetStatus

MAX_TAG_LENGTH = 50  # the `assets.tags` element size


def parse_asset_filter(args: MultiDict[str, str]) -> tuple[AssetFilter, int]:
    """`(filter, page)` from `type`, `root`, `tag`, `q`, `status`, `page`; 400 on bad values.

    Empty values mean "no filter", so a submitted filter form with blank fields works.
    """
    tag = args.get("tag", "").strip() or None
    q = args.get("q", "").strip() or None
    if (tag and len(tag) > MAX_TAG_LENGTH) or (q and len(q) > MAX_HOSTNAME_LENGTH):
        abort(400)
    try:
        flt = AssetFilter(
            type=AssetType(raw) if (raw := args.get("type")) else None,
            root_id=UUID(raw) if (raw := args.get("root")) else None,
            tag=tag,
            q=q,
            status=AssetStatus(args.get("status") or AssetStatus.ACTIVE),
        )
    except ValueError:
        abort(400)
    page = args.get("page", 1, type=int) or 1
    return flt, max(page, 1)
