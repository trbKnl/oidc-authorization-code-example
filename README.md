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

## Client application

The repostitory contains a client application called `client.py`. Its a FastAPI webapplication that:

- Logs users in with an identity provider you configured yourself (see ref)
- After log in, users can try access a protected resource (an ascii banana), after succesfull authorization the result is displayed on screen


## Protected resouce

The repostitory also contains a protected resource in the form of an API. It returns an ascii banana if the user supplies a valid access token with the correct scope.


## Identity provider that supports OpenID Connect 

I did not create this identity provider myself, I relied upon an existing identity provider

