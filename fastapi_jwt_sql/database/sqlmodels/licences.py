import datetime
from typing import List
from ..database import SQLAlchemyBase

# used to contain "Column", not replaced for mapped_column for better type hinting.
from sqlalchemy import ForeignKey, Integer, DateTime, Boolean, LargeBinary, String
from sqlalchemy.orm import mapped_column, Mapped
import sqlalchemy.orm as orm


def same_as(column_name):
    def default_function(context):
        return context.current_parameters.get(column_name)
    return default_function


# class Licence(SQLAlchemyBase):
#     __tablename__ = "licences"

#     id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
#     owners: Mapped["Owner"] = orm.relationship(
#         "Owner", back_populates="licence")
#     users: Mapped[List["User"]] = orm.relationship(
#         "Owner", back_populates="licence")
#     logged_users: Mapped[List["LoggedUser"]
#                          ] = orm.relationship(back_populates="licence")

#     serial_number: Mapped[str] = mapped_column(String)
#     total_number_of_active_users: Mapped[int] = mapped_column(Integer)
#     active: Mapped[bool] = mapped_column(Boolean)
#     valid_license: Mapped[bool] = mapped_column(Boolean)
#     valid_from: Mapped[datetime.date] = mapped_column(DateTime)
#     valid_until: Mapped[datetime.date] = mapped_column(DateTime)
#     # TODO maybe remove duration? Complicates meanings - we can simply query it if necessary. or rename.
#     # duration: Mapped[datetime.date] = mapped_column(DateTime)
#     created_on: Mapped[datetime.date] = mapped_column(
#         DateTime, default=datetime.datetime.now)


# class Owner(SQLAlchemyBase):
#     __tablename__ = 'owners'

#     # primary key automatically have indexes and a uniqueness constraint
#     id: Mapped[int] = mapped_column(
#         Integer, primary_key=True,  index=True)
#     licence_id: Mapped[int] = mapped_column(ForeignKey("licences.id"))
#     licence: Mapped["Licence"] = orm.relationship(back_populates="owner")

#     firstname: Mapped[str] = mapped_column(String)
#     surname: Mapped[str] = mapped_column(String)
#     email: Mapped[str] = mapped_column(String, unique=True, nullable=True)
#     # don't use .now(), just use .now, as it will call the function when record is being created.
#     # Otherwise it will reflect the time from when an instance of User Class was created.
#     # allow sorting, and better querying.
#     created_on: Mapped[datetime.date] = mapped_column(
#         DateTime, default=datetime.datetime.now, index=True)
#     comments: Mapped[str] = mapped_column(String)
#     affilitation: Mapped[str] = mapped_column(String,  nullable=True)


# class User(SQLAlchemyBase):
#     __tablename__ = 'users'

#     # primary key automatically have indexes and a uniqueness constraint
#     id: Mapped[int] = mapped_column(
#         Integer, primary_key=True,  index=True)
#     # licence_id: Mapped[int] = mapped_column(ForeignKey("licences.id"))
#     # licence: Mapped["Licence"] = orm.relationship(back_populates="user")

#     email: Mapped[str] = mapped_column(String, unique=True, nullable=True)
#     username: Mapped[str] = mapped_column(
#         String, unique=True, default=same_as('email'))
#     role: Mapped[str] = mapped_column(String, default="user")
#     hashed_password: Mapped[bytes] = mapped_column(LargeBinary)
#     salt: Mapped[int] = mapped_column(LargeBinary)
#     # TODO. or rephrase disabled to verified.
#     disabled: Mapped[bool] = mapped_column(Boolean, default=False)
#     is_active: Mapped[bool] = mapped_column(Boolean, default=False)
#     # don't use .now(), just use .now, as it will call the function when record is being created.
#     # Otherwise it will reflect the time from when an instance of User Class was created.
#     # allow sorting, and better querying.
#     created_on: Mapped[datetime.date] = mapped_column(
#         DateTime, default=datetime.datetime.now, index=True)
#     # last_licence_update: Mapped[datetime.date] = mapped_column(DateTime)


# class LoggedUser(SQLAlchemyBase):
#     __tablename__ = 'logged_users'

#     # primary key automatically have indexes and a uniqueness constraint
#     id: Mapped[int] = mapped_column(
#         Integer, primary_key=True,  index=True)
#     # licence_id: Mapped[int] = mapped_column(ForeignKey("licences.id"))
#     # licence: Mapped["Licence"] = orm.relationship(back_populates="loggeduser")

#     username: Mapped[str] = mapped_column(String, unique=True, nullable=True)
#     # instead of logged_in_time, created_on: entry is created at this time.
#     logged_in_on: Mapped[datetime.date] = mapped_column(
#         DateTime, default=datetime.datetime.now, index=True)
