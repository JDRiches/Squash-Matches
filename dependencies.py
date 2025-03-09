from typing import Annotated

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, create_engine


USERNAME = "root"
PASSWORD = "password"
HOST = "localhost"  # Use 'host.docker.internal' if accessing from another container
PORT = 3306
DATABASE = "squash_db"

# Create SQLAlchemy engine
DATABASE_URL = f"mysql+pymysql://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE}"

engine = create_engine(DATABASE_URL)

def get_database_session():
    """Gets a database session, ensures each requrest gets its own session"""
    with Session(engine) as session:
        yield session

DatabaseSessionDep = Annotated[Session, Depends(get_database_session)]


OAuth2SchemeDep = Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="token"))]