"""Only server-issued UUIDs can select repository storage."""
from pathlib import Path
from uuid import UUID


def repository_directory(root: str, repository_id, *, create: bool = False) -> Path:
    key = str(UUID(str(repository_id)))
    base = Path(root).absolute()
    # Storage parents are operator-managed, not selected by a request.
    for part in (base, *base.parents):
        if part.is_symlink():
            raise ValueError('Managed storage must not contain symlink parents.')
    if create:
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = base / 'repositories'
    if parent.is_symlink():
        raise ValueError('Managed storage must not contain symlinks.')
    if create:
        parent.mkdir(exist_ok=True, mode=0o700)
    directory = parent / key
    if directory.is_symlink():
        raise ValueError('Managed storage must not contain symlinks.')
    if create:
        directory.mkdir(mode=0o700)  # Exclusive, never reuse a prior workspace.
    return directory
