# OIDC Oauth2 Authorization code flow with PCKE challenge

This repostitory contains a full example of an authorization code flow with FastAPI in Python.

```
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
```

## Install dependencies

Create virtual env and install dependencies: `pip -r requirements.txt`.

## Client application

The repostitory contains a client application called `client.py`. Its a FastAPI webapplication that:

- Logs users in with an identity provider you configured yourself (see ref)
- After log in, users can try access a protected resource (an ascii banana), after succesfull authorization the result is displayed on screen

Start the client with:  `python3 -m uvicorn client:app --reload --log-level debug`

## Protected resouce API

The repostitory also contains a protected resource in the form of an API. It returns an ascii banana if the user supplies a valid access token with the correct scope.

Start the API with: `python3 -m uvicorn banana_resource:app --port 8123 --reload --log-level debug`

## Identity provider that supports OpenID Connect 

I did not create this identity provider myself, I relied upon an (existing identity provider)[https://github.com/Soluto/oidc-server-mock]. its an implementation of (Duende IdentityServer)[https://duendesoftware.com/products/identityserver], which is only free for non-commercial projects such as these.

### Usage

Pull the docker version of the identity provider.

Create the following configurations for the identity provider:

#### `./client-config.json`

The client application (in this case the web application needs) to be configured in the identity server.
You can configure this is the correct configuration for the client application in this example. 

```
[
  {
    "ClientId": "banaan-client",
    "RedirectUris": ["http://localhost:3000/auth/oidc", "http://localhost:4004/auth/oidc", "https://oidcdebugger.com/debug", "https://oauthdebugger.com/debug", "http://localhost:8000/authentication_response/"],
    "ClientSecrets": ["secret"],
    "AllowedGrantTypes": ["authorization_code"],
    "RequirePkce": true,
    "AllowedScopes": ["openid", "profile", "banaan-scope"]
  }
]
```

#### `./users.json`

In this configuration you specify all the users that your identity providers knows about. These are the users that can use the identity provider to log in to your application.

```
[
      {
        "SubjectId":"1",
        "Username":"User1",
        "Password":"pwd",
        "Claims": [
          {
            "Type": "name",
            "Value": "Turbo Knul",
            "ValueType": "string"
          },
          {
            "Type": "email",
            "Value": "knul.turbo@gmail.com",
            "ValueType": "string"
          },
          {
            "Type": "some-api-resource-claim",
            "Value": "Sam's Api Resource Custom Claim",
            "ValueType": "string"
          },
          {
            "Type": "some-api-scope-claim",
            "Value": "Sam's Api Scope Custom Claim",
            "ValueType": "string"
          },
          {
            "Type": "some-identity-resource-claim",
            "Value": "Sam's Identity Resource Custom Claim",
            "ValueType": "string"
          }
        ]
      }
]
```

#### `./api-scopes.yaml`

A custom scope that our procted resource will use

```
- Name: banaan-scope
```

#### Start the identity server

Start the identity server with the configurations:

```
docker run -p 80:80 -e API_SCOPES_INLINE="$(cat ./api-scopes.yaml)" -e CLIENTS_CONFIGURATION_INLINE="$(cat ./client-config.json)" -e USERS_CONFIGURATION_INLINE="$(cat ./users.json)" ghcr.io/soluto/oidc-server-mock:latest
```

Go to `http://localhost:80` to see the identity server in action.


