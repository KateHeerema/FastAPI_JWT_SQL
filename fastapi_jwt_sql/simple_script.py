import datetime
from typing import Annotated, Any, Literal, Optional
from uuid import uuid4
import bcrypt
import fastapi
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
import uvicorn

from fastapi import Request, status, Depends, HTTPException
import database.sqlmodels.licences as licences
from sqlalchemy.orm import Session
from database.database import SessionLocal, engine
import api.auth as auth
from api.models import CreateUserRequest, Token
from jose import ExpiredSignatureError, jwt, JWTError

# where to store these? main / auth ?
ALGORITHM = 'HS256'  # standard algorithm
SECRET_KEY = 'ThisIsTheKeyToDeCODE'

# initiate a FastAPI instance
app = fastapi.FastAPI()
# set up routers, this allows for redirects from other .py files (clean code)


SECRET_KEY = 'ThisIsTheKeyToDeCODE'
ACCESS_AUTH_TOKEN_EXPIRATION_MINUTES = 10
# 1 week.  # for now in minutes, but time_delta in generation can be updated to equal hours or days
ACCESS_REFRESH_TOKEN_EXPIRATION_MINUTES = 10080

ALGORITHM = 'HS256'  # standard algorithm

oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


# setting FastAPI dependencies. (https://fastapi.tiangolo.com/tutorial/dependencies)
refresh_tokens = {}
user_db = {}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def authenticate_user(username: str, password: str, user_db: dict):
    """Retrieve.
    Query database, using pydantic User model 

    """
# TODO consider instead of returning false, returning an HTTP401, "Incorrect username or password"
    user = user_db.get(username)
    if not user:
        return False
    # here, often CryptContext is used, but that is only for hashed_pw. this is a salted & hashed pw.
    if not bcrypt.checkpw(password.encode('utf-8'), user["hashed_password"]):
        return False
    return user


def create_jwt_token(username: str, user_id: int, type: Literal["refresh", "auth"], expires_delta: datetime.timedelta):
    """Creates authentication or refresh JWT token, and includes the type and expiration of the token.
    This can be separated into two functions, but would be very duplicated."""
    payload = {
        "sub": username,
        "id": user_id,
        "jti": str(uuid4),
        "type": type,
    }
    expires = datetime.datetime.now(datetime.UTC) + expires_delta
    payload.update({"exp": expires.timestamp()})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def add_jti_to_blacklist(jti_db, jti: str, expires_at: datetime.datetime):
    jti_to_add = {
        "token_jti": jti,
        "expires_at": expires_at,
        "added_on": datetime.datetime.now(datetime.UTC),
    }
    jti_db["token_jti"] = jti_to_add
    return jti_db


def is_jti_blacklisted(jti_db, jti) -> bool:
    jti = jti_db.get("jti")
    return not (jti is None)


@app.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(create_user_request: CreateUserRequest):
    """ Create. 
    Salting makes the password stored unique, even when different users have the same PW. """
    salt = bcrypt.gensalt()
    pw = create_user_request.password.encode('utf-8')
    create_user_model = {
        "username": create_user_request.username,
        "salt": salt,
        "hashed_password": bcrypt.hashpw(pw, salt),
    }
    user_db.update({create_user_request.username: create_user_model})
    print(user_db)


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """_
    """
    user = authenticate_user(form_data.username, form_data.password, user_db)
    if not user:
        # this causes a delay in the feedback. Unneccessary, but basically slows down malicious intent.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate user. (3)',
        )
    username = user["username"]
    user_id = 1234

    # refresh_token = create_jwt_token(
    #     username=username,
    #     user_id=user_id,
    #     type="refresh",
    #     expires_delta=datetime.timedelta(
    #         minutes=ACCESS_REFRESH_TOKEN_EXPIRATION_MINUTES),
    # )
    auth_token = create_jwt_token(
        username=username,
        user_id=user_id,
        type="auth",
        expires_delta=datetime.timedelta(
            minutes=ACCESS_AUTH_TOKEN_EXPIRATION_MINUTES),
    )

    return {"token": auth_token, "token_type": "bearer"}


def get_current_user(jti_db,  token: Annotated[str, Depends(oauth2_bearer)]):
    """Verify that current user has an active token.

    """

    # try if the AUTH token is still valid.
    print(type(token))
    print(token)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # automatically raises expired error if expired.
        username = payload.get("sub")
        token_type = payload.get("type")
        jti = payload.get("jti")
        # TODO: why are we checking username and id again? This is checked when the token is generated.
        if is_jti_blacklisted(jti_db, jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Login expired, please login again (1).")
        if username is None or token_type != "auth":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials (1).")

        return {"username": username}
    # Third, if not valid, Check if Refresh token is still valid. If yes, generate new AUTH token.
    except ExpiredSignatureError:
        try:
            refresh_payload = jwt.decode(
                token, SECRET_KEY, algorithms=[ALGORITHM])
            jti = payload.get("jti")
            if is_jti_blacklisted(jti_db, jti):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Login expired, please login again(2).")
            if username is None or token_type != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials (2).")
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user (1).")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user (2).")


@app.get("/")
def home():
    return {"hello: this is a  homepage accessible to all"}


@app.get("/secret", status_code=status.HTTP_200_OK)
async def user(user: Annotated[dict, Depends(get_current_user)]):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    # return {"User": user}
    return "This is a secret site, only accessible when logged in."


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0")
