from fastapi import HTTPException
from sqlalchemy.orm import Session
from session.models.ORMmodels import ORMPost


def create_post(db: Session, title: str, content: str, user_id: int, existing_post: ORMPost):
    if existing_post:
        raise HTTPException(status_code=401, detail=("this title is used"))

    # ORMPost defines the column as `titel` (typo preserved in the model)
    # create the instance using the correct attribute name
    new_post = ORMPost(title=title, content=content, user_id=user_id)

    db.add(new_post)
    db.commit()
    db.refresh(new_post)
    return {"message": "post registered successfully", "title": new_post.title}


def get_mypost(information: ORMPost):
    if not information:
        return []
    return [{"title": post.title, "content": post.content} for post in information]


def get_allposts(information: ORMPost):
    if not information:
        return []
    return [{"title": post.title, "content": post.content} for post in information]


def Update_post(db: Session, title: str, content: str, post: ORMPost):
    if post.title is not None and post.content is not None:
        post.title = title
        post.content = content
    db.commit()
    db.refresh(post)
    return {"message": "Update is successful"}


def Delete_post(db: Session, post: ORMPost):

    db.delete(post)
    db.commit()
    return {"message": "Delete is successful"}
