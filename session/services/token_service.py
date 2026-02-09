from fastapi import HTTPException, Response, Request, Depends
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from session.models.ORMmodels import ORMUser
from session.models.ORMmodels import ORMRefreshToken
from session.security.jwt_handler import (
    create_access_token,
    create_refresh_token,
    create_csrf_token,
)
from session.security.rate_limit import register_failed_login, _get_device_identifier
from session.core.redis import redis_client
import uuid


pwd = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
csrf_header_name = "X-CSRF-Token"


def hash_password(password: str) -> str:
    return pwd.hash(password)


def generate_device_id():
    return str(uuid.uuid4())


def get_csrf_cookie(request: Request) -> str:
    crsf_cookie = request.cookies.get("csrf_token")
    return crsf_cookie


def check_token(
    request: Request, response: Response, db: Session, username: str, password: str
):
    existing_user = db.query(ORMUser).filter(ORMUser.username == username).first()
    if not existing_user:
        register_failed_login(request=request)
        raise HTTPException(status_code=401, detail="Username not found")

    # model stores hashed password in `hashed_password`
    if not pwd.verify(password, existing_user.hashed_password):
        register_failed_login(request=request)
        raise HTTPException(status_code=401, detail="Invalid password")

    device_id = generate_device_id()
    response.set_cookie(
        key="device_id",
        value=device_id,
        httponly=False,  # dev
        secure=False,  # dev
        samesite="lax",
    )
    csrf_token = create_csrf_token()
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,  # dev
        secure=False,  # dev
        samesite="lax",
    )
    device_ip = request.client.host()

    access_token = create_access_token(
        {
            "id": existing_user.id,
            "sub": existing_user.username,
            "role": existing_user.role,
        }
    )
    refresh_token = create_refresh_token()
    cre = datetime.now()
    exp = datetime.now() + timedelta(days=7)
    db.add(
        ORMRefreshToken(
            token=refresh_token,
            expires_at=exp,
            user_id=existing_user.id,
            device_id=device_id,
            created_at=cre,
            last_used_at=cre,
            device_ip=device_ip,
        )
    )
    db.commit()
    response = JSONResponse({"access_token": access_token})
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # dev
        samesite="lax",
    )
    return response


def check_refresh(
    request: Request,
    db: Session,
    response: Response,
    csrf_token_header: str = Depends(get_csrf_cookie),
):
    csrf_header = request.headers.get(csrf_header_name)
    if not csrf_header:
        raise HTTPException(status_code=403, detail="CSRF Token Missing in Header")

    if csrf_header != csrf_token_header:
        raise HTTPException(status_code=403, detail="CSRF Token Mismatch")
    refrech_token = request.cookies.get("refresh_token")
    device_id = request.cookies.get("device_id")
    if not refrech_token or not device_id:
        raise HTTPException(status_code=401, detail="Not authrnticated")

    token_db = (
        db.query(ORMRefreshToken)
        .filter(
            ORMRefreshToken.token == refrech_token,
            ORMRefreshToken.device_id == device_id,
        )
        .first()
    )

    if not token_db:
        raise HTTPException(status_code=401, detail="Invalid refersh token")

    if token_db.expires_at < datetime.now():
        db.delete(token_db)
        db.commit()
        raise HTTPException(status_code=401, detail="Expired refersh token")

    if token_db.is_revoked:
        device = _get_device_identifier(request=request)
        ban_key = f"ban:{device}"
        redis_client.setex(ban_key,600,"1")
        db.query(ORMRefreshToken).filter(
            ORMRefreshToken.device_id == token_db.device_id
        ).update({"is_revoked": True})
        db.commit()
        response.delete_cookie("refresh_token", httponly=True)
        raise HTTPException(status_code=401, detail="Session Compromised")

    if token_db.last_used_at:
        token_db.last_used_at = datetime.now()

    token_db.is_revoked = True
    user = db.get(ORMUser, token_db.user_id)
    device_ip = request.client.host()
    access_token = create_access_token(
        {
            "id": user.id,
            "sub": user.username,
            "role": user.role,
        }
    )
    new_refresh_token = create_refresh_token()
    cre = datetime.now()
    exp = datetime.now() + timedelta(days=7)
    db.add(
        ORMRefreshToken(
            token=new_refresh_token,
            expires_at=exp,
            user_id=user.id,
            device_id=device_id,
            created_at=cre,
            last_used_at=cre,
            device_ip=device_ip,
        )
    )
    db.commit()
    response = JSONResponse({"access_token": access_token})
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
    )
    return response


def delete_rfresh(
    request: Request,
    db: Session,
    response: Response,
    csrf_token_header: str = Depends(get_csrf_cookie),
):
    csrf_header = request.headers.get(csrf_header_name)
    if not csrf_header:
        raise HTTPException(status_code=403, detail="CSRF Token Missing in Header")

    if csrf_header != csrf_token_header:
        raise HTTPException(status_code=403, detail="CSRF Token Mismatch")

    refresh_token = request.cookies.get("refresh_token")
    device_id = request.cookies.get("device_id")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Not authrnticated")

    token_db = (
        db.query(ORMRefreshToken)
        .filter(
            ORMRefreshToken.token == refresh_token,
            ORMRefreshToken.device_id == device_id,
            ORMRefreshToken.is_revoked == False,
        )
        .first()
    )
    if token_db:
        token_db.is_revoked = True
        db.commit()
    response = JSONResponse({"massage": "logged out"})
    response.delete_cookie("refresh_token")
    response.delete_cookie("device_id")
    return response


def delete_all_refresh(
    request: Request,
    db: Session,
    response: Response,
    user: ORMUser,
    csrf_token_header: str = Depends(get_csrf_cookie),
):
    csrf_header = request.headers.get(csrf_header_name)
    if not csrf_header:
        raise HTTPException(status_code=403, detail="CSRF Token Missing in Header")

    if csrf_header != csrf_token_header:
        raise HTTPException(status_code=403, detail="CSRF Token Mismatch")

    update = (
        db.query(ORMRefreshToken)
        .filter(ORMRefreshToken.user_id == user.id, ORMRefreshToken.is_revoked == False)
        .update({"is_revoked": True})
    )
    db.commit()
    response = JSONResponse({"massage": "logged out"})
    response.delete_cookie("refresh_token")
    response.delete_cookie("device_id")
    return response
