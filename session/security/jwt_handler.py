from datetime import datetime, timedelta
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from DATABASE.db import get_db
from session.models.ORMmodels import ORMUser
import secrets

SECRET_KEY = "ypur-very-long-random-secret-key-here-1234567890!@#$%^&*()_2026"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def create_access_token(data: dict, expire: timedelta | None = None):
    to_encode = data.copy()

    if expire:
        exp = datetime.now() + expire
    else:
        exp = datetime.now() + timedelta(hours=1)

    to_encode.update({"type": "access", "exp": exp})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token():
    return secrets.token_urlsafe(48)


def create_csrf_token():
    return secrets.token_urlsafe(48)


def decode_access_token(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):

    try:

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        username: str | None = payload.get("sub")
        role: str | None = payload.get("role")
        type: str | None = payload.get("type")

        if username is None or role is None or type != "access":
            raise HTTPException(status_code=401, detail="Invalid token payload")

        # load user from DB to ensure it still exists and fetch current role
        user = db.query(ORMUser).filter(ORMUser.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return {"sub": user.username, "role": user.role, "id": user.id}

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: {e}",
            headers={"WWW-Authorization": "Bearer"},
        )
