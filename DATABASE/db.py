from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base


URL_DATABASE = "postgresql://ahmed_2:123@localhost/pro"
engine = create_engine(URL_DATABASE)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
