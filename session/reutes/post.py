from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from DATABASE.db import get_db
from session.security.jwt_handler import decode_access_token
from session.services.post_service import (
    create_post,
    get_mypost,
    get_allposts,
    Update_post,
    Delete_post,
)
from session.security.PermissionsPost import (
    check_post_me,
    check_post_all,
    check_post_Update,
    check_post_Delete,
)
from session.models.RegisterModels import CreatePost, UpDatePost
from session.models.ORMmodels import ORMPost

router = APIRouter()


@router.post("/Create")
async def CreatePosts(
    Post: CreatePost,
    current: dict = Depends(decode_access_token),
    db: Session = Depends(get_db),
):
    existing_post = db.query(ORMPost).filter(ORMPost.title == Post.title).first()
    user_id = current.get("id")
    return create_post(
        db=db,
        title=Post.title,
        content=Post.content,
        user_id=user_id,
        existing_post=existing_post,
    )


@router.get("/posts/me")
async def get_post(
    current: dict = Depends(decode_access_token), db: Session = Depends(get_db)
):
    check_post_me(current=current)
    id = current.get("id")
    information = db.query(ORMPost).filter(ORMPost.user_id == id).all()
    return get_mypost(information=information)


@router.get("/posts/all")
async def get_post(
    current: dict = Depends(decode_access_token), db: Session = Depends(get_db)
):
    check_post_all(current=current)
    information = db.query(ORMPost).all()
    return get_allposts(information=information)


@router.put("/update/{post_id}")
async def UpdatePosts(
    post_id: int,
    use: UpDatePost,
    current: dict = Depends(decode_access_token),
    db: Session = Depends(get_db),
):
    post_info = db.query(ORMPost).filter(ORMPost.id == post_id).first()
    check_post_Update(post=post_info, current=current)

    return Update_post(db=db, post=post_info, title=use.title, content=use.content)


@router.delete("/delete/{post_id}")
async def delete(
    post_id: int,
    current: dict = Depends(decode_access_token),
    db: Session = Depends(get_db),
):
    target_post = db.query(ORMPost).filter(ORMPost.id == post_id).first()
    check_post_Delete(post=target_post, current=current)

    return Delete_post(db=db, post=target_post)
