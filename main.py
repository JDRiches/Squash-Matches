from fastapi import Depends, FastAPI

from .users import user_router

app = FastAPI()


app.include_router(user_router)

