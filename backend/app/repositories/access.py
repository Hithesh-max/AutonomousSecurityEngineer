from sqlalchemy.orm import Session
from app.models.project import Project, Target
from app.models.user import User
from app.utils.validators import is_url_in_scope


def require_authorized_target(db: Session, target_id, user_id) -> Target:
    # populate_existing avoids stale authorization values held in the identity map.
    target = db.query(Target).populate_existing().filter(Target.id == target_id).first()
    user = db.query(User).populate_existing().filter(User.id == user_id).first()
    project = db.query(Project).populate_existing().filter(Project.id == target.project_id).first() if target else None
    if not user or not user.is_active or not target or not project or project.owner_id != user_id:
        raise PermissionError('Project access is unavailable.')
    if target.authorization_status != 'APPROVED' or not target.is_active:
        raise PermissionError('Target authorization is unavailable.')
    if not target.explicit_scope or not is_url_in_scope(target.url, target.explicit_scope):
        raise PermissionError('Target is outside approved scope.')
    return target
