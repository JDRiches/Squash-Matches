from .users_models import Token, TokenData, User, UserCreate, UserPublic
from ..dependencies import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, SECRET_KEY, DatabaseSessionDep, GetUserDep, get_user

from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
import jwt

from sqlmodel import Session
from passlib.context import CryptContext

from decouple import config
from motor import motor_asyncio

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

user_router = APIRouter(
    prefix="/user",
    tags=["user"],
)

# def verify_password(plain_password, hashed_password):
#     """Checks to see if password is correct"""
#     return pwd_context.verify(plain_password, hashed_password)


# def authenticate_user(session: Session, username: str, password: str) -> Optional[User]:
#     """Check whether the given user exists and whether the password hashes match"""
#     user = get_user(username, session)
#     if not user:
#         return False
#     if not verify_password(password, user.hashed_password):
#         return False
#     return user

# def create_access_token(data: dict, expires_delta: timedelta | None = None):
#     """Create an access token for the logged in user"""
#     to_encode = data.copy() 
#     if expires_delta:
#         expire = datetime.now(timezone.utc) + expires_delta
#     else:
#         expire = datetime.now(timezone.utc) + timedelta(minutes=15)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt


# @user_router.post("/token")
# async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: DatabaseSessionDep) -> Token:
#     """Endpoint to log the user in and send them a token"""
#     user = authenticate_user(session, form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
#     return Token(access_token=access_token, token_type="bearer")


# @user_router.get("/me", response_model=UserBase)
# async def get_logged_in_user(current_user: GetUserDep):
#     """Endpoint to get details of user currently logged in"""
#     return current_user

@user_router.post("/register", response_model=UserPublic)
async def register_new_user(user: UserCreate):
    """Register a new user with the app"""
    print("starting connection")
    DB_CONNECTION_STRING = config("DB_CONNECTION_STRING")
    client = motor_asyncio.AsyncIOMotorClient(DB_CONNECTION_STRING)
    print("client made")
    db = client.get_database("sqaush_db")
    print("datavase got")
    users_collection = db.get_collection("users")
    print("collection got")

    user = User(
        username="jriches",
        email="jriches@mail.com",
        full_name="Jack Riches",
        hashed_password="$2y$10$wQ7RQxStekc2SHykQQPmEuapOg64b5QhIWHLaJwfsVokyBFZLtRSy",
    )
    new_user = await users_collection.insert_one(user.model_dump(by_alias=True, exclude=["id"]))

    return
    create_user = UserCreate.model_validate(user)
    db_user = User(**create_user.model_dump())
    
    if get_user(db_user.username, session): 
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists",
            )

    hashed_password = pwd_context.hash(user.password)
    db_user.hashed_password = hashed_password

    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user