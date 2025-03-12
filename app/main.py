from fastapi import Depends, FastAPI
from sqlmodel import SQLModel

from .users.users import user_router
from .matches.matches import matches_router
from .dependencies import engine

app = FastAPI()


app.include_router(user_router)
app.include_router(matches_router)


SQLModel.metadata.create_all(engine)
