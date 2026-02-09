from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from DATABASE.db import get_db
from session.security.jwt_handler import decode_access_token
from session.models.ORMmodels import ORMUser
from session.models.RegisterModels import UpdateUser
from session.services.user_service import get_allusers, update_user, delete_user
from session.security.PermissionsUser import (
    check_allusers,
    check_user_update,
    check_user_delete,
)

router = APIRouter()


@router.get("/profile")
async def profile(current: dict = Depends(decode_access_token)):
    return {
        "id": current.get("id"),
        "username": current.get("sub"),
        "role": current.get("role"),
    }


@router.get("/allusers")
async def admin(current: dict = Depends(decode_access_token), db: Session = Depends(get_db)):
    check_allusers(current=current)
    return get_allusers(db=db)


@router.put("/Update/{username}")
async def update(
    username: str,
    use: UpdateUser,
    current: dict = Depends(decode_access_token),
    db: Session = Depends(get_db),
):
    target = db.query(ORMUser).filter(ORMUser.username == username).first()
    check_user_update(target=target, username=username, use=use, current=current, db=db)
    return update_user(target=target, db=db)


@router.delete("/delete/{username}")
async def delete(
    username: str, current: dict = Depends(decode_access_token), db: Session = Depends(get_db)
):
    target = db.query(ORMUser).filter(ORMUser.username == username).first()
    check_user_delete(target=target, current=current)
    return delete_user(target=target, db=db)
