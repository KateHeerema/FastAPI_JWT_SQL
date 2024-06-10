# This .py file is for Pydantic models, used in the FastAPI api to verifiy input/output.

import datetime
from typing import Optional
from pydantic import BaseModel


# pydantic models
class CreateUserRequest(BaseModel):  # pydantic data validation
    username: str
    password: str


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
