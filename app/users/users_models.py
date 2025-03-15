from typing import Annotated, Optional
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

PyObjectId = Annotated[str, BeforeValidator(str)]

class UserPublic(BaseModel):
    username: str = Field()
    email: str  = Field()
    full_name: str = Field()
    profile_pic_url: str | None = Field(default=None)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "username": "jdoe",
                "email": "jdoe@example.com",
                "full_name": "John Doe",
                "profile_pic_url": "somecdn.com/sfeesfsefjnewg",
                "hashed_password": "hfebhufewhuwfehuwfe",
                "disabled": "false",
            }
        },
    )

class User(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    username: str = Field()
    email: str  = Field()
    full_name: str = Field()
    profile_pic_url: str | None = Field(default=None)
    hashed_password: str | None = Field(default=None)
    disabled: bool = Field(default=False)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "username": "jdoe",
                "email": "jdoe@example.com",
                "full_name": "John Doe",
                "profile_pic_url": "somecdn.com/sfeesfsefjnewg",
                "hashed_password": "hfebhufewhuwfehuwfe",
                "disabled": "false",
            }
        },
    )

class UserCreate(BaseModel):
    username: str = Field()
    email: str  = Field()
    full_name: str = Field()
    password: str = Field()

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
