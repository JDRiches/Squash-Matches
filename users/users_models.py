from pydantic import BaseModel
from sqlmodel import Field, SQLModel


class UserBase(SQLModel):
    username: str = Field(default=None, index=True)
    email: str | None = Field(default=None)
    full_name: str | None = Field(default=None)

class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str
    disabled: bool | None = Field(default=None)

class UserCreate(UserBase):
    password: str = Field(default=None)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
