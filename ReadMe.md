# Login / Licence / FastAPI Considerations

## Background, System requirements

The Cytofit project requirements are as follows:

1. Be able to give a single licence to an institute.
2. This licence needs to be able to associate an X amount of *Active Users* at any one time.
3. The licence needs to be able to have >X amount of *Users* associated to it.
4. Principally, login once, stayed logged in for a substantial amount of time (~Indefinitely)
5. Ability to actively log out, and free up a licence allocation.
6. Associate data to each log-in / user session.
7. Our application is a Single Page Application (SPA).

## Session Management

Two main approaches to maintain a login sessions:

- JWT "Jot" JSON Web Tokens
- Cookies

These are fundamentally different. Cookies are a storage of arbitrary data, whereas JWT are authorization data. More [alternatives](https://fastapi-users.github.io/fastapi-users/latest/configuration/authentication/) exist.

### JWT
It is also called a "stateless" approach, since no “state” or “session” is saved within a DB (it is contained within the JWT token itself). Information is passed through the Authorization header. 
Principally, it has not expiration, and it is not stored anywhere. Best practice is to create two tokens: a short-lived authorization token (~15 min) and a longer lived refresh token (~weeks), which are stored in separate places. This would generate an external check on authorization check, but would principally limit re-authorization of the user to the expiration of the refresh token. A JWT consists of three parts: Header, Payload, Signature separated by a ( . ). The Header typically contains the algorithm and the type of token (JWT). The Payload contains all the claims, i.e. all additional information such as exp, jti, iss. Should be kept at a minimum to keep the size of a JWT minimal. The Signature is based on the previous information, generated automatically.
Cons: No apparent Logout system (only expiration).
Pros: Scalable as it is stateless.

The logout system for JWT would be to implement a blacklist of tokens that have expired. This will have to be checked for every call that requires authentication. 

### Cookies
Name-Value pair of a unique sessionID, stored in a web browser. Every request verifies the stored Session ID to a sessionDB, making this approach "stateful"
 
Cons:  Individual servers cannot be scaled separately since they would need to share the sessionDB. (If you use cookies to protect your web service, that service needs to live on the domain for which the authentication cookies are set, as the same-origin policy won't send cookies to another domain.)
Pros: precision logout. logout occurs at the moment the sessionID is removed from the sessionDB.

[Security considerations](https://stackoverflow.com/questions/41614259/jwt-authentication-refresh-token-implementation?rq=3):
- Use `httponly=True` to prevent XSS attacks (Cross-Site Scripting)
- Vulnerable to CSRF (Cross-Site Request Forgery) Attacks. 
- Store a JWT in a httponly cookie for the best 

### Conclusions.
We will use JWT due to its scalability. For logout purposes, we will create a Database TokenBlacklist which would keep track of all Tokens no longer valid. 
It is worth considering storing JWT tokens in a cookie instead of the authorisation header. This needs further consideration if it is actually more secure, and isn't essential.

Requires to separate databases:
1. TokenBlacklist. TokenId(JTI) / Created_at      #make the JTI index=True for faster searching. can make a UUID instead of JTI if preferred. 
2. JWT secret

# Licence
The current plan is to make a DB network to keep track of licencing. There are also other platforms offering Licencing as a Service (LaaS). For instance [Cryptolens](https://help.cryptolens.io) or [NetLicensing] (https://netlicensing.io). This could be worth considering when scaling up. 
The Databases structure would be as follows (Bold are connected fields):

1. Licences. **UUID** / Serial / no of Users / Active / Valid / ValidFrom / ValidTo / Duration / CreatedOn
2. Owners. **UUID** / Name / Surname / Email / CreatedOn / Comments / ?Affiliation / {Extra registration info}
3. Users. **UUID** / Email / Username / Role / Password / CreatedOn / LastLicenceUpdate / Verified
4. Logged. **UUID** / Email / LoggedInTime


# FastAPI

Application Programming Interface (API). FastAPI is a backend application that deals with information, handling client demands, and delivering reactions between different application and/or servers. It is used for the creation of HTTP endpoints: for instance `get` `post`  `delete` requests.
[useful examples](https://refine.dev/blog/introduction-to-fast-api/#file-uploads)

**Browser** --*request from user* --> **API deals with request (DB call, middleware, etc)** --*display request*

## Build on

1. Uvicorn (web server)
2. Starlette, ASGI framework. Handles routing, middleware, request/response flow. Allows for independent choices in ORM and database tools. 
3. Pydantic. A Python data validation model. The "shape" of data is declared as a class. 

## Cool features / integrations

1. Middleware. Use for universal issues, ie logging or error handling, or to integrate other applications.  It is a function that works on every request before it is processed by any specific path operation and on every response before returning it.
2. Asynchronous code, using coroutines: `async with .. as ..` + `await` pair or `async` + `await`, also known as "concurrency". Different from parallelization! Don't overuse as it can overcomplicate code, and might depend on support from third party library. Useful for "slow" tasks, and better for scaling up. But can be introduced in later stages too. For instance:
   1. DB calls
   2. Write to disk
   3. Route data across network
3. Routers let you subdivide the code into separate scripts, whilst still only running one API instance.
4. Use swagger (or postman) to test code, no need for frontend to be in place to test the API. Swagger is found at localhost URL generated when running the api: <<local_url/docs>>.  Postman is an app (and has more extensive, paid, possibilities).
5. [fastapi-users](https://fastapi-users.github.io/fastapi-users/latest/) library.



## TODOs

1. Make all the DB calls async
   1. Make the related fastapi code a co-routine (Async + Await)
2. Add refresh tokens. (Perhaps wait for a fastapi update?)
3. Automatically clean the JTI blacklist (ie clean up every entry that has expired at the end of a work day / once a week)
4. update User model in Pydantic to have two separate classes (with/without pw)
5. Store the token blacklist database in a Redis database: It will be faster. 
6. store JWT (only refresh? both?) in a http-only cookie. (is this major refactoring for the auth JWT?)
7. 