# the main page initiating the REST API, and establishing connections.
import datetime
from typing import Annotated, Optional
import uvicorn
import logging
import fastapi
from fastapi import status, Depends, HTTPException
from fastapi_jwt_sql.database.database import engine
from fastapi_jwt_sql.api.auth import add_jti_to_blacklist, auth_router, db_dependency, get_active_user
from fastapi_jwt_sql.api.auth import get_current_user
from .database.sqlmodels import licences
from . import config_rootlogger

# initiate a FastAPI instance
api = fastapi.FastAPI()
# set up routers, this allows for redirects from other .py files
api.include_router(auth_router)

# database init. The details are setup in database.database.py
licences.SQLAlchemyBase.metadata.create_all(bind=engine)

# define the user dependency, checking the current user
# Annotated is adding metadata to request params, adding data validations.
user_dependency = Annotated[dict, Depends(get_current_user)]

# for developing purposes: set up logging.
config_rootlogger()
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# check all fastapi endpoints without needing a frontend by using the swagger documentation:
# add "/docs" to the url.

# open endpoint
@api.get("/")
def home() -> set[str]:
    return {"hello: this is a  homepage accessible to all"}


# secured endpoint
@api.get("/secret_page", status_code=status.HTTP_200_OK)
async def user(user: user_dependency) -> dict[str, user_dependency]:
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    return {"User": user}


# logout functionality is adding the jti to a blacklist
@api.post("/logout")
async def logout(active_user: Annotated[dict, Depends(get_active_user)], db: db_dependency):
    jti: Optional[str] = active_user.get("jti")
    exp: Optional[float] = active_user.get("exp")
    if exp and jti is not None:
        exp_timestamp: datetime.date = datetime.datetime.fromtimestamp(exp)
        add_jti_to_blacklist(jti=jti, expires_at=exp_timestamp,
                             db=db)
    return {"logout successful": active_user}


# this is running the api, can specify port as well.
if __name__ == "__main__":
    uvicorn.run(api, host="0.0.0.0")
