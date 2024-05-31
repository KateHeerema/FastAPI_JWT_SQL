

# templates = Jinja2Templates("frontend/templates")


# TODO allow pw change.


def update_user():
    return None


# Admin only.
def delete_user():
    return None

# Make db calls async? (then DB also needs async set up. )


# add role checker.


# @api.post("/logout", response_model=Token)
# # logout function to delete access token
# async def logout(current_user = Depends(get_current_user)):
#     token_data = TokenData(username=current_user.username, expires=0)
#     return token_data


# @api.post("/logout")
# async def logout(token: str, db: Annotated[Session, Depends(get_db)]):
#     try:
#         # TODO, where to put these global variables?
#         payload: dict[str, Any] = jwt.decode(
#             token, SECRET_KEY, algorithms=[ALGORITHM])
#         jti = payload.get("jti")
#         # TODO does this make sense to raise, for a logout -- Also doubles up with the except statement.
#         if jti is None:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
#         expires: Optional[int] = payload.get("exp")
#         if expires:
#             expire = datetime.datetime.fromtimestamp(expires)
#         # TODO make this an await - make db async
#         add_jti_to_blacklist(db, jti, expires)  # type: ignore
#         return "Logged out successfully."
#     except JWTError:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# @api.get("/data")
# def get_data(_: Annotated[bool, Depends(RoleChecker(allowed_roles=["admin"]))]):
#   return {"data": "This is important data only accessible by <admin>."}


# @api.get("/auth/login", response_class=HTMLResponse)
# def login_get(request: Request):
#     context = {
#         "request": request,
#     }
#     return templates.TemplateResponse("login.html", context)


# def create_licence_entry(db: Annotated[Session, Depends(get_db)]):
#     licence_to_add = licences.Licence(
#         serial_number="123abc",
#         total_number_of_active_users=2,
#         active=True,
#         valid_licence=True,
#         valid_from=datetime.datetime.now(
#             datetime.UTC) - datetime.timedelta(days=7),
#         valid_until=datetime.datetime.now(
#             datetime.UTC) + datetime.timedelta(days=7),
#         created_on=datetime.datetime.now(datetime.UTC),
#     )
#     db.add(licence_to_add)
#     return db.commit()


# def create_owner_entry():
#     owner_to_add = licences.Owner(
#         firstname="first",
#         surname="last",
#         email="first.last@me.no",
#         created_on=datetime.datetime.now(datetime.UTC),
#         comments="",
#     )
#     db = get_db()
#     db.add(owner_to_add)
#     return db.commit()


# def create_user():


# auth:
  # except ExpiredSignatureError:
    #     try:
    #         refresh_payload = jwt.decode(
    #             token, SECRET_KEY, algorithms=[ALGORITHM])
    #         jti = payload.get("jti")
    #         if is_jti_blacklisted(db, jti):
    #             raise HTTPException(
    #                 status_code=status.HTTP_401_UNAUTHORIZED, detail="Login expired, please login again.")
    #         if username is None or token_type != "refresh":
    #             raise HTTPException(
    #                 status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials.")
    #     except JWTError:
    #         raise HTTPException(
    #             status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user.")
