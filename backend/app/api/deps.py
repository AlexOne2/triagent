import secrets
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from app.core.config import get_settings
from app.db.session import get_db

security = HTTPBasic(auto_error=False)


def require_basic_auth(
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
    settings=Depends(get_settings),
):
    if not settings.admin_username or not settings.admin_password:
        return
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auth required")
    valid_user = secrets.compare_digest(credentials.username, settings.admin_username)
    valid_pass = secrets.compare_digest(credentials.password, settings.admin_password)
    if not (valid_user and valid_pass):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


__all__ = ["get_db", "require_basic_auth"]
