from fastapi import HTTPException
from session.models.ORMmodels import ORMPost


def check_post_me(current: dict):
    role = current.get("role")
    if not role:
        raise HTTPException(status_code=403, detail="Access denied")
    return


def check_post_all(current: dict):
    role = current.get("role")
    if role not in ["moderator", "admin"]:
        raise HTTPException(status_code=401, detail="can't access for users")
    return


def check_post_Update(post: ORMPost, current: dict):
    if not post:
        raise HTTPException(status_code=404, detail="post not found")
    role = current.get("role")
    user_id = current.get("id")

    if role == "admin":
        return
    if post.user_id != user_id:
        raise HTTPException(status_code=404, detail="postnot found")
    return


def check_post_Delete(post: ORMPost, current: dict):
    if not post:
        raise HTTPException(status_code=404, detail="post not found")

    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return
