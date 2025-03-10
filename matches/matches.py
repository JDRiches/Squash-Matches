from fastapi import APIRouter
from sqlmodel import Field, SQLModel
from datetime import datetime

from ..dependencies import DatabaseSessionDep, GetUserDep


class MatchBase(SQLModel):
    p1_id: int = Field(index=True, foreign_key="user.id")
    p2_id: int = Field(index=True, foreign_key="user.id")
    p1_score: int = Field(default=0)
    p2_score: int = Field(default=0)
    date_time: datetime = Field(default= None)


class Match(MatchBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    owner: int = Field(foreign_key="user.id")
    winner: int = Field(foreign_key="user.id")


matches_router = APIRouter(
    prefix="/matches",
    tags=["matches"],
)

@matches_router.post("/submit")
async def submit_match(match: MatchBase, user: GetUserDep, session: DatabaseSessionDep):
    create_match = MatchBase.model_validate(match)
    db_match = Match(**create_match.model_dump())
    db_match.owner = user.id

    if db_match.p1_score > db_match.p2_score:
        db_match.winner = db_match.p1_id
    else:
        db_match.winner = db_match.p2_id

    session.add(db_match)
    session.commit()
    session.refresh(db_match)

    return db_match


