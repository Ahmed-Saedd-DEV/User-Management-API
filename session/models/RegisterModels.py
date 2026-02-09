from pydantic import BaseModel


class RegisterUser(BaseModel):
    username: str
    password: str
    role: str


class LoginUser(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class UpdateUser(BaseModel):
    username: str | None = None
    password: str | None = None
    role: str | None = None


class CreatePost(BaseModel):
    title: str
    content: str


class UpDatePost(BaseModel):
    title: str | None = None
    content: str | None = None
