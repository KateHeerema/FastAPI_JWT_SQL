import datetime

from sqlalchemy import DateTime, String
from ..database import SQLAlchemyBase
from sqlalchemy.orm import mapped_column, Mapped


class RefreshTokens(SQLAlchemyBase):
    __tablename__ = "refreshtokens"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    refresh_token: Mapped[str] = mapped_column(String)
    created_on: Mapped[datetime.date] = mapped_column(
        DateTime, default=datetime.datetime.now)


class TokenBlacklist(SQLAlchemyBase):
    __tablename__ = "tokenblacklist"

    token_jti: Mapped[str] = mapped_column(String, primary_key=True)
    expires_at: Mapped[datetime.date] = mapped_column(
        DateTime, default=datetime.datetime.now)
    added_on: Mapped[datetime.date] = mapped_column(
        DateTime, default=datetime.datetime.now)
