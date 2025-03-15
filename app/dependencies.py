from typing import Annotated, Optional

#from decouple import config
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from sqlmodel import SQLModel, Session, create_engine, select

from .users.users_models import User, TokenData

import os
from motor import motor_asyncio
from dotenv import load_dotenv

SECRET_KEY = "ba00cc705314719c9de5f15c5659c41615bd15eeef3ea25550954070ca190e06"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
load_dotenv()

def get_database_session():
    """Gets a database session, ensures each request gets its own session"""
    DB_CONNECTION_STRING = os.getenv("DB_CONNECTION_STRING")
    client = motor_asyncio.AsyncIOMotorClient(DB_CONNECTION_STRING)  
    yield client.get_database("squash_db").get_collection()

DatabaseSessionDep = Annotated[Session, Depends(get_database_session)]

OAuth2SchemeDep = Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="token"))]

# TODO: Maybe split this out into common functions file or something
def get_user(username: str, session: Session) -> Optional[User]:
    """Get user from database matching the supplied username"""

    statement = select(User).where(User.username == username)
    result = session.exec(statement)
    user = result.first()
    return user

async def get_current_user(token: OAuth2SchemeDep, session: DatabaseSessionDep) -> Optional[User]:
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

GetUserDep = Annotated[User, Depends(get_current_user)]





