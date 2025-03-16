import os
from .users_models import Token, TokenData, User, UserCreate, UserPublic
from ..dependencies import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, SECRET_KEY, DatabaseClientDep, GetUserDep, get_user_by_username

from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
import jwt

from passlib.context import CryptContext

from motor.motor_asyncio import AsyncIOMotorCollection
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

user_router = APIRouter(
    prefix="/user",
    tags=["user"],
)

def verify_password(plain_password, hashed_password):
    """Checks to see if password is correct"""
    return pwd_context.verify(plain_password, hashed_password)


async def authenticate_user(user_collection: AsyncIOMotorCollection, username: str, password: str) -> Optional[User]:
    """Check whether the given user exists and whether the password hashes match"""
    user = await get_user_by_username(username, user_collection)
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


@user_router.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], client: DatabaseClientDep) -> Token:
    """Endpoint to log the user in and send them a token"""

    user_collection: AsyncIOMotorCollection = client.get_collection("users")
    user = await authenticate_user(user_collection, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")


@user_router.get("/me", response_model=UserPublic)
async def get_logged_in_user(current_user: GetUserDep):
    """Endpoint to get details of user currently logged in"""
    return current_user

@user_router.post("/register", response_model=UserPublic)
async def register_new_user(user: UserCreate, client: DatabaseClientDep):
    """Register a new user with the app"""

    create_user = UserCreate.model_validate(user)
    db_user = User(**create_user.model_dump())

    # Check if the user already exists in the database

    hashed_password = pwd_context.hash(user.password)
    db_user.hashed_password = hashed_password

    users_collection: AsyncIOMotorCollection = client.get_collection("users")
    new_user = await users_collection.insert_one(db_user.model_dump(by_alias=True, exclude=["id"]))
    created_user = await users_collection.find_one({"_id": new_user.inserted_id})
    return created_user