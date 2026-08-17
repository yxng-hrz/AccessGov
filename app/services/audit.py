from sqlalchemy.orm import Session

from app.models import AuditEvent


def log_event(
    db: Session,
    event_type: str,
    actor: str = "system",
    entity_type: str = "",
    entity_id: str = "",
    details: str = "",
) -> AuditEvent:
    event = AuditEvent(
        event_type=event_type,
        actor=actor,
        entity_type=entity_type,
        entity_id=str(entity_id),
        details=details,
    )
    db.add(event)
    return event
