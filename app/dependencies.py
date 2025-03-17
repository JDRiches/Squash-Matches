from typing import Annotated, Optional

#from decouple import config
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from sqlmodel import SQLModel, Session, create_engine, select
from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorClient

from .users.users_models import User, TokenData

import os

from dotenv import load_dotenv

SECRET_KEY = "ba00cc705314719c9de5f15c5659c41615bd15eeef3ea25550954070ca190e06"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
load_dotenv()

DB_CONNECTION_STRING = os.getenv("DB_CONNECTION_STRING")
client = AsyncIOMotorClient(DB_CONNECTION_STRING)  
def get_database_client():
    """Gets a database session, ensures each request gets its own session"""
    return client.get_database("squash_db")

DatabaseClientDep = Annotated[AsyncIOMotorClient, Depends(get_database_client)]

OAuth2SchemeDep = Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="token"))]

# TODO: Maybe split this out into common functions file or something
async def get_user_by_username(username: str, user_collection: AsyncIOMotorCollection) -> Optional[User]:
    """Get user from database matching the supplied username"""
    user = await user_collection.find_one({"username": username})
    print(user)
    return User(**user)


async def get_current_user(token: OAuth2SchemeDep, client: DatabaseClientDep) -> Optional[User]:
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
    user = await get_user_by_username(token_data.username, client.get_collection("users"))
    if user is None:
        raise credentials_exception
    return user

GetUserDep = Annotated[User, Depends(get_current_user)]



