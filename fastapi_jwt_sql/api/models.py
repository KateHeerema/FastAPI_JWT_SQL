# This .py file is for Pydantic models, used in the FastAPI api to verifiy input/output.

import datetime
from typing import Optional
from pydantic import BaseModel


# pydantic models
class CreateUserRequest(BaseModel):  # pydantic data validation
    username: str
    password: str

# TODO update user request to the following. Update the databse model to include extra params.


class User(BaseModel):
    username: str
    email: str
    disabled: bool


class UserInDB(User):
    hashed_password: str

# class Token(BaseModel):  # necessary token validation for login user authentication
#     access_token: str
#     refresh_token: str
#     token_type: str


class Token(BaseModel):  # necessary token validation for login user authentication
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
    expires: datetime.datetime


class UserAPI(BaseModel):
    username: str
    email: str
    disabled: str
    hashed_password: str

# class
# class UserAPI(BaseModel):
#     username: str
#     email: str
#     disabled: str
#     # role: str
#     hash: str
#     hashed_password: str
