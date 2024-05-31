import datetime
from typing import List
from ..database import SQLAlchemyBase

# used to contain "Column", not replaced for mapped_column for better type hinting.
from sqlalchemy import ForeignKey, Integer, DateTime, Boolean, LargeBinary, String
from sqlalchemy.orm import mapped_column, Mapped
import sqlalchemy.orm as orm


class Users(SQLAlchemyBase):
    __tablename__ = 'users'

    # primary key automatically have indexes and a uniqueness constraint
    id: Mapped[int] = mapped_column(
        Integer, primary_key=True,  index=True)

    # email: Mapped[str] = mapped_column(String, unique=True, nullable=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    hashed_password: Mapped[bytes] = mapped_column(LargeBinary)
    # created_on: Mapped[datetime.date] = mapped_column(
    #     DateTime, default=datetime.datetime.now, index=True)
