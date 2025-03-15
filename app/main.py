from fastapi import Depends, FastAPI

from motor import motor_asyncio

from decouple import config
from .users.users import user_router
from .users.users_models import User

# from .matches.matches import matches_router


app = FastAPI()


app.include_router(user_router)
# app.include_router(matches_router)
