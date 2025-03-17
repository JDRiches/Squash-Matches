from typing import Annotated, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from datetime import datetime

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


from ..dependencies import DatabaseClientDep, GetUserDep

from motor.motor_asyncio import AsyncIOMotorCollection
PyObjectId = Annotated[str, BeforeValidator(str)]

class CreateMatch(BaseModel):
    p1_id: str = Field()
    p2_id: str = Field()
    p1_score: int = Field()
    p2_score: int = Field()
    date_time: datetime = Field()

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "p1_id": "23",
                "p2_id": "4324",
                "p1_score": "11",
                "p2_score": "4",
                "date_time": "11-11-2025",
            }
        },
    )

class Match(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    p1_id: str = Field()
    p2_id: str = Field()
    p1_score: int = Field()
    p2_score: int = Field()
    owner: str | None = Field(default= None)
    winner: str | None = Field(default= None)
    date_time: datetime = Field()
    confirmed: bool = Field(default=False)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "p1_id": "23",
                "p2_id": "4324",
                "p1_score": "11",
                "p2_score": "4",
                "owner": "23",
                "winner": "23",
                "date_time": "11-11-2025",
            }
        },
    )

class MatchCollection(BaseModel):
    matches: List[Match]

matches_router = APIRouter(
    prefix="/matches",
    tags=["matches"],
)

@matches_router.post("/submit", response_model=Match)
async def submit_match(match: CreateMatch, user: GetUserDep, client: DatabaseClientDep):
    """Create a match, with the owner being the user who submitted the match"""

    # Check if boths ids are valid
    # Check if scores are valid
    # CHeck if date is in the past or now

    create_match = CreateMatch.model_validate(match)
    db_match = Match(**create_match.model_dump())
    db_match.owner = user.id

    if db_match.p1_score > db_match.p2_score:
        db_match.winner = db_match.p1_id
    else:
        db_match.winner = db_match.p2_id

    match_collection: AsyncIOMotorCollection = client.get_collection("matches")
    new_match = await match_collection.insert_one(db_match.model_dump(by_alias=True, exclude=["id"]))
    created_match = await match_collection.find_one({"_id": new_match.inserted_id})
    return created_match

@matches_router.get("/history/{user_id}", response_model=MatchCollection)
async def get_match_history(user_id: str, user: GetUserDep, client: DatabaseClientDep):
    """Get the match history for a user"""

    # Can only get the match history of yourself, maybe from friends later
    if user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid permissions",
            headers={"WWW-Authenticate": "Bearer"},
        )

    match_collection: AsyncIOMotorCollection = client.get_collection("matches")

    matches = await match_collection.find({"$or": [{"p1_id": user_id}, {"p2_id": user_id}]}).to_list(1000)

    return MatchCollection(matches = matches, )

@matches_router.get("/pending/{user_id}", response_model=MatchCollection)
async def get_pending_matches(user_id: str, user: GetUserDep, client: DatabaseClientDep):
    
    # Can only get the match history of yourself, TODO: Make this a dep or middleware
    if user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid permissions",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    match_collection: AsyncIOMotorCollection = client.get_collection("matches")
    pending_matches = await match_collection.find({"$or": [{"p1_id": user_id}, {"p2_id": user_id}], "owner": {"$ne": user_id}, "confirmed": False}) .to_list(1000)
    return MatchCollection(matches=pending_matches)
