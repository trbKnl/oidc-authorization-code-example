from typing import Annotated
import logging
import requests

from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

# Configure the logging format and level
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

LOGGER = logging.getLogger(__name__)

OPENID_PROVIDER = "http://localhost"
BANANA = r"""
/\
V  \
 \  \_
  \,'.`-.
   |\ `. `.       
   ( \  `. `-.                        _,.-:\
    \ \   `.  `-._             __..--' ,-';/
     \ `.   `-.   `-..___..---'   _.--' ,'/
      `. `.    `-._        __..--'    ,' /
        `. `-_     ``--..''       _.-' ,'
          `-_ `-.___        __,--'   ,'
             `-.__  `----'''    ___-'
                  `--..____..--'
"""

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.get("/get_ascii_banana")
async def get_ascii_banana(access_token: Annotated[str, Depends(oauth2_scheme)]):
    """
    FastApi helps us with the oauth2_scheme
    The access_token will be equal to the Bearer token in the request.

    If a Bearer token was supplied, the function body begins:
    1. Get the signing key id and the encryption algorithm, that the jwt has been signed with
    2. Get that signing key from the oidc provider
    3. Verify and decode the jwt
    4. Verify if the jwt has the correct banaan-scope 
    5. On success return the banana
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        decoded_header = jwt.get_unverified_header(access_token)
        kid = decoded_header.get('kid', "")         # get the key id
        alg = decoded_header.get('alg', "")         # get the signing algorithm
        key = get_key_from_oidc_provider(kid)

        # Validate the jwt
        payload = jwt.decode(access_token, key, algorithms=[alg])

        # Check if the correct scope is included
        # This API will only return the ascii banana
        # if banaan-scope is included in the token
        if "banaan-scope" not in payload.get("scope", []):
            raise credentials_exception

    except JWTError as e:
        LOGGER.error(e)
        raise credentials_exception

    return {"payload": BANANA}



def get_key_from_oidc_provider(kid: str):
    """
    Get the JSON Web Key Set from the oidc provider

    Return the key that matches the key identifier (kid)
    """
    jwks_endpoint = f"{OPENID_PROVIDER}/.well-known/openid-configuration/jwks"
    response = requests.get(jwks_endpoint)
    jwks = response.json()
    desired_key = {}

    for key in jwks.get('keys', []):
        if key.get('kid') == kid:
                desired_key = key

    return desired_key
