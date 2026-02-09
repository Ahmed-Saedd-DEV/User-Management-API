from fastapi import APIRouter, Depends, Response, Request
from sqlalchemy.orm import Session
from DATABASE.db import get_db
from session.services.user_service import add_user
from session.services.token_service import (
    check_token,
    check_refresh,
    delete_rfresh,
    delete_all_refresh,
)
from session.models.ORMmodels import ORMUser
from session.security.jwt_handler import decode_access_token
from session.models.RegisterModels import RegisterUser, LoginUser
from session.security.rate_limit import rate_limit_refresh, rate_limit_login

router = APIRouter()


@router.post("/register")
async def add_register(use: RegisterUser, db: Session = Depends(get_db)):
    """Register a new user. db is a SQLAlchemy Session provided by the dependency."""
    return add_user(db=db, username=use.username, password=use.password, role=use.role)


@router.post("/login")
async def login(
    request: Request,
    use: LoginUser,
    response: Response,
    db: Session = Depends(get_db),
    _: None = Depends(rate_limit_login),
):
    return check_token(
        request=request,
        response=response,
        db=db,
        username=use.username,
        password=use.password,
    )


@router.post("/refresh")
async def refrech(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _: None = Depends(rate_limit_refresh),
):
    return check_refresh(request=request, response=response, db=db)


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    return delete_rfresh(request=request, response=response, db=db)


@router.post("/logout_all")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current: ORMUser = Depends(decode_access_token),
):
    return delete_all_refresh(request=request, response=response, db=db, user=current)
