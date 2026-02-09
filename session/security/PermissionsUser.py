from fastapi import HTTPException
from sqlalchemy.orm import Session
from session.models.ORMmodels import ORMUser
from session.models.RegisterModels import UpdateUser
from session.services.user_service import hash_password


def check_allusers(current:dict):
    if current.get("role") not in ["moderator", "admin"]:
        raise HTTPException(status_code=403, detail="false access")
    
    
def check_user_update(target: ORMUser, username:str, use: UpdateUser, current: dict, db: Session):
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    role = current.get("role")

    # admin: can change username, password, role
    if role == "admin":
        if use.username:
            # ensure new username is not already used by another user
            existing = (
                db.query(ORMUser).filter(ORMUser.username == use.username).first()
            )
            if existing and existing.id != target.id:
                raise HTTPException(status_code=400, detail="username is used")
            target.username = use.username
        if use.password:
            target.hashed_password = hash_password(use.password)
        if use.role:
            target.role = use.role

    # moderator: can change username and password
    elif role == "moderator":
        if use.username:
            existing = (
                db.query(ORMUser).filter(ORMUser.username == use.username).first()
            )
            if existing and existing.id != target.id:
                raise HTTPException(status_code=400, detail="username is used")
            target.username = use.username
        if use.password:
            target.hashed_password = hash_password(use.password)

    # user: can change own username/password only

    elif role == "user":
        if current.get("sub") != username:
            raise HTTPException(status_code=403, detail="Access denied")
        if use.username:
            existing = (
                db.query(ORMUser).filter(ORMUser.username == use.username).first()
            )
            if existing and existing.id != target.id:
                raise HTTPException(status_code=400, detail="username is used")
            target.username = use.username
        if use.password:
            target.hashed_password = hash_password(use.password)

    else:
        raise HTTPException(status_code=403, detail="Access denied")


def check_user_delete(target: ORMUser, current: dict):
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied")