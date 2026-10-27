from uuid import uuid4

from attacksurf.domain.events import ScanCompleted
from attacksurf.infra.events import InProcessDispatcher


def test_failing_event_handler_does_not_prevent_other_handlers() -> None:
    dispatcher = InProcessDispatcher()
    received = []

    def fail(event: object) -> None:
        raise RuntimeError("secret must not be logged")

    dispatcher.handlers.extend((fail, received.append))
    event = ScanCompleted(uuid4(), uuid4())
    dispatcher.publish(event)
    assert received == [event]
