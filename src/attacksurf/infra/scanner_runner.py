"""Bound scanner wall time without letting a late result write to the database."""

from concurrent.futures import Future, TimeoutError
from threading import BoundedSemaphore, Thread

from attacksurf.domain.scanners import AssetRef, ScanContext, Scanner, ScannerError, ScanOutput

# Threads cannot be killed. Bound abandoned work per worker process; prefork children recycle
# after 100 tasks. Network adapters must also enforce their own deadlines.
_slots = BoundedSemaphore(4)


def run_scanner(scanner: Scanner, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
    slots = _slots
    if not slots.acquire(blocking=False):
        raise ScannerError("Scanner capacity exhausted by unfinished checks.")
    future: Future[ScanOutput] = Future()

    def run() -> None:
        try:
            future.set_result(scanner.run(ctx, asset))
        except Exception as exc:
            future.set_exception(exc)
        except BaseException:
            future.set_exception(ScannerError("Scanner terminated unexpectedly."))
        finally:
            slots.release()

    try:
        Thread(target=run, daemon=True, name="scanner").start()
    except BaseException:
        slots.release()
        raise
    try:
        output = future.result(timeout=scanner.timeout_seconds)
    except TimeoutError:
        raise ScannerError("Scanner exceeded its time budget.") from None
    # Revalidate even pre-built models: nested containers may have been mutated by a plugin.
    return ScanOutput.model_validate(output.model_dump(mode="json"))
