# This file is to create a database. This should be transferable to a cloud-based database.
# SQLAlchemy is the connector between whatever database & your application.
# provides option for ORM (object relational mapper)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import DeclarativeBase

# old import, used to be standard import/set up of base class (often referenced still online)
# from sqlalchemy.ext.declarative import declarative_base


# Session: unit of work, internally manages the connection.

# To explore any SQLite database, you can install "DB Browser for SQLite" application.

# location + name of the database
SQLALCHEMY_DATABASE_URL = 'sqlite:///./fastapi_jwt_sql/database/userauthenticationapp.db'

# Uses connection URL, returns sqlalchemy engine.
# Echo to True to get SQL commands sent to db (standard out, standard error?)
# Connection can be used by multiple threads (other than the one that created it)
engine = create_engine(SQLALCHEMY_DATABASE_URL, echo=False, connect_args={
                       'check_same_thread': False})

# Creates a callable, which will create a unit of work / sessions.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Factory method to generate base classes at runtime. BaseClass for the SQL models.
# Can be multiple for each db you want to target. associate with a DB connection & a class (in the models).
# but every table in this one db should be derived from "SQLAlchemyBase" -- all stored in one.

# new method, works better with Type hinting in Python.


class SQLAlchemyBase(DeclarativeBase):
    pass

# old style, more commonly referred to online:
# SQLAlchemyBase = declarative_base()
