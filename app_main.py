from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from session.reutes import auth, users, post
from session.models import ORMmodels
from session.security.security_headers import SecurityHeadersMiddleware
from DATABASE.db import engine

app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000"],
    allow_methodes=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)
ORMmodels.Base.metadata.create_all(bind=engine)


app.include_router(auth.router, prefix="/auth")
app.include_router(users.router, prefix="/users")
app.include_router(post.router, prefix="/post")
