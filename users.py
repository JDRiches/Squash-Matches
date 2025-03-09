from dependencies import DatabaseSessionDep

from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
import jwt
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select
from passlib.context import CryptContext

class UserBase(SQLModel):
    username: str = Field(default=None, index=True)
    email: str | None = Field(default=None)
    full_name: str | None = Field(default=None)
    disabled: bool | None = Field(default=None)

class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None




SECRET_KEY = "ba00cc705314719c9de5f15c5659c41615bd15eeef3ea25550954070ca190e06"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

#SQLModel.metadata.create_all(engine)


def get_user(username: str, session: DatabaseSessionDep) -> Optional[User]:
    """Get user from database matching the supplied username"""

    statement = select(User).where(User.username == username)
    result = session.exec(statement)
    user = result.first()
    return user

def verify_password(plain_password, hashed_password):
    """Checks to see if password is correct"""
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(session: DatabaseSessionDep, username: str, password: str) -> Optional[User]:
    """Check whether the given user exists and whether the password hashes match"""
    user = get_user(username, session)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Create an access token for the logged in user"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: DatabaseSessionDep) -> Token:
    # Check user exists and password is correct
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")

