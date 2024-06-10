# The main authentication page, connecting fastapi with database calls.
from fastapi_jwt_sql.database.database import SessionLocal
from .models import CreateUserRequest, Token
import bcrypt
import datetime
from datetime import timedelta
from typing import Annotated, Any, Generator, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException
from starlette import status
from uuid import uuid4

from ..database.sqlmodels.jwt_tokens import TokenBlacklist
from ..database.sqlmodels.models import Users
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError, ExpiredSignatureError
from sqlalchemy.orm import Session

import logging

# for debugging purposes. For example:logger.debug(token) will return the token in the terminal and specify which file.
logger = logging.getLogger(__name__)


# the router allows for separating sections, as a subsidiary of the api.py file.
# this router needs to be linked in the main.py file. The "/auth" prefix makes all endpoints here start with /auth
# the t
auth_router = APIRouter(prefix="/auth", tags=["authentication purposes"])

# These parameters are necessary for the JWT Token.
# use the following to create a random key: openssl rand -hex 32
SECRET_KEY = 'ThisIsTheKeyToDeCODE'
ALGORITHM = 'HS256'  # standard algorithm
ACCESS_AUTH_TOKEN_EXPIRATION_MINUTES = 1

# Pointing to the location of the token, the endpoint is defined lower down in the code.
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")


###
# TODO: is the output type correct? Suggested from vscode.
def get_db() -> Generator[Session, Any, None]:
    """Create a single session for you database request.

    Yields:
        The database connection.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Annotated is used with Python Types to add metadata to request parameters.
# because the db_dependency is used in multiple places,
# we can declare it here and store the annotated value in a variable, to avoid repeat code.
db_dependency = Annotated[Session, Depends(get_db)]


def authenticate_user(username: str, password: str, db: Session):
    """Verification of the username and password, check if exists in the database.

    Args:
        username: 
            username as is stored in the database
        password: 
            user password, will be just a string, but will not be visible in the process. 
        db :
            the 

    Returns:
        Pointer to the User entry following the Users SQLAlchemy scheme. 

    Raises:
        KeyError if username is not known in database. 
        ValueError if password is incorrect.
    """
    user: Optional[Users] = db.query(Users).filter(
        Users.username == username).first()
    if not user:
        raise KeyError("User not found.")
    # here, often CryptContext is used, but that is only for hashed_pw. this is a salted & hashed pw.
    if not bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
        raise ValueError("Password incorrect.")
    return user


def _create_jwt_token(username: str, user_id: int, type: Literal["refresh", "auth"], expires_delta: datetime.timedelta) -> str:
    """Creates a jwt (JSON Web Token), requires the global/environment variables SECRET_KEY and ALGORTIHM.

    Args:
        username: 
            unique username, matches database
        user_id: 
            user_id, index of the database. Automatically generated with a new entry to database. 
        type: 
            To help identify the token type. 
        expires_delta: 
            Custom setting to determine the time of expiration. 

    Returns:
        The JWT for authentication. 
    """
    payload = {
        "sub": username,
        "id": user_id,
        "jti": uuid4().hex,
        "type": type,
    }
    expires = datetime.datetime.now(datetime.UTC) + expires_delta
    payload.update({"exp": expires.timestamp()})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def add_jti_to_blacklist(db: db_dependency, jti: str, expires_at: datetime.datetime) -> None:
    """Adding the unique JWT identifier (JTI) to the blacklist. 
    This is a functionality to "log out" with JWT. Typically, JWT will persist until expired, but a blacklist 
    + internal check can provide a log out functionality.

    Args:
        db: 
            The database hosting the token blacklist
        jti: 
            Automatically generated unique string (uuid.hex4()) to identify the jwt.
        expires_at: 
            Datetime of token expiration. Allows for cleaning of database.
    """
    jti_to_add = TokenBlacklist(
        token_jti=jti,
        expires_at=expires_at,
        added_on=datetime.datetime.now(datetime.UTC),
    )
    db.add(jti_to_add)
    db.commit()


def is_jti_blacklisted(db: db_dependency, jti) -> bool:
    """Database check if a user (token) was previously logged out.

    Args:
        db:
            The database hosting the token blacklist. 
        jti: 
            The unique identifier of a JWT.

    Returns:
        True if JWT is blacklisted. 
    """
    jti = db.query(TokenBlacklist).filter_by(token_jti=jti).scalar()
    return not (jti is None)


# Salting makes the password stored unique by adding extra characters, even when different users have the same PW.
# The salt does not need to be stored because it is part of the hash produced by bcrypt.hashpw()
# TODO: catch the error when username is not unique.
@auth_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    """ Creates a user entry, salts and hashes the password, sot

    Args:
        db: 
            Dependency injection, the table used here keeps track of all user entries.  
            The table structure should follow the pydantic model.
        create_user_request: 
            Follows the defined pydantic model
    """
    salt = bcrypt.gensalt()
    pw = create_user_request.password.encode('utf-8')
    create_user_model = Users(
        username=create_user_request.username,
        hashed_password=bcrypt.hashpw(pw, salt),
    )
    db.add(create_user_model)
    db.commit()


@auth_router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: db_dependency) -> dict[str, str]:
    """Key functionality that checks database for username and password, using a FastAPI form. 

    Args:
        form_data: 
            Based on FastAPI Request form which is a class dependency that declares a form body.
            Retrieves specifically "username" and "password".

    Returns:
        The token, following the specified Token pydantic model.

    Raises:
        HTTPException: When authentication of the user fails, exception is raised.
    """
    try:
        user: Users = authenticate_user(
            form_data.username, form_data.password, db)
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user. (1)")

    auth_token = _create_jwt_token(
        username=user.username,
        user_id=user.id,
        type="auth",
        expires_delta=timedelta(minutes=ACCESS_AUTH_TOKEN_EXPIRATION_MINUTES),
    )
    # active_user = LoggedUser(username=user.username,
    #                          logged_in_on=datetime.datetime.now(datetime.UTC))
    # db.add(active_user)
    # db.commit()

    # return needs to match the structure of the fastapi pydantic model of type Token
    return {
        "access_token": auth_token,
        "token_type": "bearer"
    }


async def get_current_user(db: db_dependency, token: Annotated[str, Depends(oauth2_bearer)]) -> dict[str, Any]:
    """Logic to validate user, by checking for active user and if the jti is not blacklisted. 
    TODO: implement logic with refresh token, (also not blacklisted), if valid generate a new auth token.

    Args:
        db: 
            DB dependency, to check if jti is blacklisted
        token:
            The authentication token, retrieved from the token url. 

    Returns:
        The active user dict {username, jti, exp}

    Raises HTTPException when login is expired, or could not validate the user.  
    """

    try:
        active_user = get_active_user(token)
        jti = active_user.get("jti")

        if is_jti_blacklisted(db=db, jti=jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="You logged out. Log in again.")
    except ExpiredSignatureError:
        # TODO ("let's do something useful here, including refresh token check. ")
        active_user = get_active_user(token)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Login Expired, log in again. (2)")
    # # Third, if not valid, Check if Refresh token is still valid. If yes, generate new AUTH token.
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user. (2)")
    return active_user


def get_active_user(token: Annotated[str, Depends(oauth2_bearer)]) -> dict[str, Any]:
    """Checks the validity of the token.

    Args:
        token:
            Dependency of the OAuth2PasswordBearer, this is where the token is stored. 

    Raises an HTTPException when the user is not logged in, could not be verified or if JWT cannot be verified.

    Returns a dict with the key user information.
    """
    # TODO: Is this none doing anything?
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not logged in.")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # automatically raises expired error if expired.
        username = payload.get("sub")
        jti: str = payload.get("jti")  # type:ignore
        exp = payload.get("exp")
        if username is None or jti is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials. (2)")
        return {"username": username, "jti": jti, "exp": exp}
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="You are logged out.")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user. (3)")

# TODO


def refresh_authentication_token():
    # check if refresh token is not expired
    # check if refresh token is not blacklisted
    # generate a new auth_token
    # return new auth token
    pass
