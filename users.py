from .dependencies import DatabaseSessionDep

from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select
from passlib.context import CryptContext

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




SECRET_KEY = "ba00cc705314719c9de5f15c5659c41615bd15eeef3ea25550954070ca190e06"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

user_router = APIRouter(
    prefix="/user",
    tags=["user"],
)

#SQLModel.metadata.create_all(engine)


def get_user(username: str, session: Session) -> Optional[User]:
    """Get user from database matching the supplied username"""

    statement = select(User).where(User.username == username)
    result = session.exec(statement)
    user = result.first()
    return user

def verify_password(plain_password, hashed_password):
    """Checks to see if password is correct"""
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(session: Session, username: str, password: str) -> Optional[User]:
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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], session: DatabaseSessionDep):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.InvalidTokenError:
        raise credentials_exception
    user = get_user(token_data.username, session)
    if user is None:
        raise credentials_exception
    return user



@user_router.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: DatabaseSessionDep) -> Token:
    """Endpoint to log the user in and send them a token"""
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


@user_router.get("/me", response_model=UserBase)
async def get_logged_in_user(current_user: Annotated[UserBase, Depends(get_current_user)]):
    """Endpoint to get details of user currently logged in"""
    return current_user

@user_router.post("/register", response_model=UserBase)
async def register_new_user(user: UserCreate, session: DatabaseSessionDep):
    """Register a new user with the app"""
    create_user = UserCreate.model_validate(user)

    db_user = User(**create_user.model_dump())
    
    hashed_password = pwd_context.hash(user.password)
    db_user.hashed_password = hashed_password

    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user