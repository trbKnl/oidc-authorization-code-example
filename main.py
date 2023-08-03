from dataclasses import dataclass, asdict
import urllib.parse
import uuid
import pprint
import secrets
import requests
import logging
import hashlib
import base64
import json
import re

from fastapi import FastAPI, Depends, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

# Configure the logging format and level
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

@dataclass
class OIDCConfig:
    openid_provider: str
    redirect_uri: str
    response_type: str
    response_mode: str
    scope: str
    client_id: str

@dataclass
class AuthenticationRequestQueryParams:
    client_id: str
    redirect_uri: str
    response_type: str
    response_mode: str
    scope: str
    state: str
    nonce: str
    code_challenge: str
    code_challenge_method: str

@dataclass
class AuthenticationResponseQueryParams:
    code: str | None = None
    scope: str | None = None
    state: str | None = None
    session_state: str | None = None
    iss: str | None = None
    error: str| None = None
    
OIDC_CONFIG = OIDCConfig(
    openid_provider="http://localhost",
    redirect_uri="http://localhost:8000/authentication_response/",
    response_type="code",
    response_mode="query",
    scope="openid profile banaan-scope",
    client_id="banaan-client"
)
CLIENT_SECRET = "secret"
LOGGER = logging.getLogger(__name__)


app = FastAPI()

#################################################
# Routes:
#
# * /                          Serves the main page
# * /authenticate              The users wants to login
# * /authentication_response   Receives the result from the oidc provider, logs the user in on success
# * /logged_in                 Serves the page for logged in users
# * /logout                    User logout
# * /get_banana                Gets banana from a resource


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):

    main_page = get_page("./static/index.html")
    response = HTMLResponse(content=main_page)
    _, response = create_session(request, response)

    return response


@app.get("/authenticate")
async def redirect_to_user_to_oidc_login(request: Request):
    """
    This route starts the authentication flow for a user, 
    it redirects the user to the oidc provider's login page
    """

    session_id = get_session_id(request)
    if session_id is None:
        return RedirectResponse("/")

    code_verifier = generate_code_verifier()
    set_session_value(session_id, "code_verifier", code_verifier)

    auth_endpoint = f"{OIDC_CONFIG.openid_provider}/connect/authorize"
    query_params = AuthenticationRequestQueryParams(
        client_id               = OIDC_CONFIG.client_id,
        redirect_uri            = OIDC_CONFIG.redirect_uri,
        response_type           = OIDC_CONFIG.response_type,
        response_mode           = OIDC_CONFIG.response_mode,
        scope                   = OIDC_CONFIG.scope,
        state                   = secrets.token_urlsafe(32),
        nonce                   = secrets.token_urlsafe(32),
        code_challenge          = generate_code_challenge(code_verifier),
        code_challenge_method   = "S256"
    )

    authentication_request_url = f"{auth_endpoint}?{urllib.parse.urlencode(asdict(query_params))}"
    response = RedirectResponse(authentication_request_url)
    log_authentication_request(auth_endpoint, query_params, authentication_request_url)

    return  response


@app.get("/authentication_response")
async def code_exchange(request: Request, query_params: AuthenticationResponseQueryParams = Depends()):
    """
    This route receives the code from the oidc provider in the query parameters.
    It then exchanges the code for an access token by POSTing it to the token endpoint.
    """
    log_authentication_response(query_params)

    session_id = get_session_id(request)
    if session_id is None:
        return RedirectResponse("/")

    code_verifier = get_session_value(request, "code_verifier")
    access_token = exchange_code_for_access_token(query_params.code, code_verifier)
    if access_token is None:
        return RedirectResponse("/")
    else:
        # If an access token was granted store the token in the session and log the user in
        set_session_value(session_id, "access_token", access_token) 
        set_session_value(session_id, "logged_in", True) 
        return RedirectResponse("/logged_in")



@app.get("/logged_in")
async def serve_logged_in_page(request: Request):

    # Make sure the user is logged in
    if is_logged_in(request) is not True:
        return RedirectResponse("/")

    logged_in_page = get_page("./static/logged_in.html")

    # Obtain the user's name from the identity provider and insert it into the page
    access_token = get_session_value(request, "access_token")
    name = get_name_from_userinfo_endpoint(access_token)
    logged_in_page = insert_name_into_html(logged_in_page, name)

    return  HTMLResponse(content=logged_in_page)
    


@app.get("/logout")
async def logout(request: Request):

    if is_logged_in(request) is True:
        delete_session(request)

    return RedirectResponse("/")


@app.get("/get_banana")
async def get_banana(request: Request):
    """
    Request a banana from the protected endpoint
    We supply the access token using the Bearer authorization scheme
    """
    access_token = get_session_value(request, "access_token")
    banana_endpoint = "http://localhost:8123/get_ascii_banana"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(banana_endpoint, headers=headers)
    data = response.json()

    if response.status_code == 200:
        out = data["payload"]
    else:
        out = json.dumps(data)

    return out


#################################################
# Functions used in routes

def exchange_code_for_access_token(code: str, code_verifier: str):
    """
    Exchange the code for an access token by posting the code to the token endpoint
    """

    token_endpoint = f"{OIDC_CONFIG.openid_provider}/connect/token"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "authorization_code",
        "redirect_uri": OIDC_CONFIG.redirect_uri,
        "code": code,
        "client_id": OIDC_CONFIG.client_id,
        "client_secret": CLIENT_SECRET,
        "code_verifier": code_verifier
    }

    log_code_exchange_request(token_endpoint, headers, data)

    # POST the code to the oidc server's token endpoint
    response = requests.post(token_endpoint, headers=headers, data=data)
    log_code_exchange_response(response.json())

    return response.json().get("access_token", None)


def get_name_from_userinfo_endpoint(access_token):
    userinfo_endoint = f"{OIDC_CONFIG.openid_provider}/connect/userinfo"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(userinfo_endoint, headers=headers)
    return response.json().get("name", None)


def get_page(path):
    with open(path, "r") as f:
        page = f.read()
    return page


def is_logged_in(request: Request):
    """
    Checks if the current session is logged in
    """
    return get_session_value(request, "logged_in")


def insert_name_into_html(page, name):
    pattern = r'===NAME==='
    page = re.sub(pattern, name, page, flags=re.MULTILINE)
    return page


def generate_code_verifier(length=64):
    return secrets.token_urlsafe(length)

def generate_code_challenge(verifier):
    """Generate a code challenge from the code verifier."""
    sha256_verifier = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(sha256_verifier).rstrip(b'=').decode()


#################################################
# session management function

SERVER_SESSION_STORAGE = {}

def get_session_id(request: Request) -> str | None:
    session_id = request.cookies.get("toy_example_client", None)
    if session_id in SERVER_SESSION_STORAGE:
        return session_id
    else:
        return None


def create_session(request: Request, response: Response) -> (str, Response):
    session_id = get_session_id(request)
    if session_id is None:
        session_id = uuid.uuid4().hex
        response.set_cookie("toy_example_client", session_id)
        SERVER_SESSION_STORAGE[session_id] = {}
    else:
        if session_id not in SERVER_SESSION_STORAGE:
            SERVER_SESSION_STORAGE[session_id] = {}

    return session_id, response


def delete_session(request: Request):
    session_id = get_session_id(request)
    if session_id is not None:
        SERVER_SESSION_STORAGE[session_id] = {}


def get_session_value(request, key):
    session_id = get_session_id(request)
    return SERVER_SESSION_STORAGE.get(session_id, {}).get(key, None)


def set_session_value(session_id, key, value):
    SERVER_SESSION_STORAGE[session_id][key] = value


#################################################
# Logger functions

# Color escape codes
GREEN = "\033[92m"  # Green color
RESET = "\033[0m"   # Reset color
BLUE = "\033[94m"  # Blue color


def log_authentication_request(auth_endpoint, query_params, authentication_request_url):
    LOGGER.info(f"""
    {BLUE}============================================
    Authentication request{RESET}

    {GREEN}Authentication request endpoint:{RESET} {auth_endpoint}
    {GREEN}Query parameters{RESET}: {pprint.pformat(query_params)}
    {GREEN}Authentication request url{RESET}: {authentication_request_url}

    {BLUE}============================================{RESET}
    """)


def log_authentication_response(auth_response):
    LOGGER.info(f"""
    {BLUE}============================================
    Authentication response{RESET}

    the openid provider GET requested {OIDC_CONFIG.redirect_uri} with query parameters
    The query parameters contain the code that can be exchanged for an access token

    {GREEN}Body:{RESET} {pprint.pformat(auth_response)}

    {BLUE}============================================{RESET}
    """)


def log_code_exchange_request(token_endpoint, headers, data):
    LOGGER.info(f"""
    {BLUE}============================================
    Exchange Code for an access token: request{RESET}

    The client request an access token in exchange for the code

    {GREEN}Token endpoint:{RESET} {token_endpoint}
    {GREEN}Headers {RESET}: {pprint.pformat(headers)}
    {GREEN}Post form{RESET}: {pprint.pformat(data)}

    {BLUE}============================================{RESET}
    """)


def log_code_exchange_response(data):
    LOGGER.info(f"""
    {separator_string()}
    {color_blue("Exchange Code for an access token: Response")}

    Response from the oidc provider

    {color_green("Response data:")} {pprint.pformat(data)}

    {separator_string()}
    """)


def color_blue(input):
    return f"{BLUE}{input}{RESET}"

def color_green(input):
    return f"{GREEN}{input}{RESET}"

def separator_string():
    return f"{BLUE}============================================{RESET}"
