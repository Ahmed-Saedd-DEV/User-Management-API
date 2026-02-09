from fastapi import HTTPException
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from session.models.ORMmodels import ORMUser



# Use a single password context. Keep argon2 first so existing argon2 hashes verify.
pwd = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd.hash(password)


def add_user(db: Session, username: str, password: str, role: str = "user"):
    """Create a new user if username is not used.

    Notes:
    - Query the ORMUser model (not the column) when checking existence.
    - Return a useful response.
    """
    existing_user = db.query(ORMUser).filter(ORMUser.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="username is used")

    hashed_password = hash_password(password)
    new_user = ORMUser(username=username, hashed_password=hashed_password, role=role)
    db.add(new_user)
    db.commit()
    # refresh to populate generated fields (id, defaults)
    db.refresh(new_user)

    return {"message": "user registered successfully", "user_id": new_user.id}


def get_allusers(db: Session):
    users = db.query(ORMUser).all()
    return [{"id": u.id, "username": u.username, "role": u.role} for u in users]


def update_user(target: ORMUser, db: Session):
    db.commit()
    db.refresh(target)
    return {"message": "Update is successful"}


def delete_user(target: ORMUser, db: Session):
    db.delete(target)
    db.commit()
    return {"message": "Delete is successful"}
