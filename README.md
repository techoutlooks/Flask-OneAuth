# Flask-OneAuth 

Centralised & pluggable user management facility for Flask.
Flask-OneAuth is a Flask extension that works with Flask-SQLAlchemy to provide 
a User model, RESTFul authentication and CRUD views for user management 

Cf. the [demo](../demo/__init__.py) app for usage in a project.


### Demo example (Facebook)

### Step 1: Get OAuth credentials

You must set the application's authorization callback URL to http://localhost:5000/auth/<provider>/authorized.

Eg., Facebook: create a `Facebook Login` app at [Facebook Developers](https://developers.facebook.com/apps)
Add http://localhost:5000/auth/facebook/authorized/ to `Valid OAuth Redirect URIs`

### Step 2: Install code and dependencies

```shell
git clone https://github.com/techoutlooks/Flask-OneAuth
cd Flask-OneAuth/src
python3 -m venv venv
source venv/bin/activate
python setup.py develop
```

### Step 3: Set environment variables

* FLASK_APP: set this to `demo`
* SECRET_KEY=$(openssl rand -base64 32)
* OAUTHLIB_INSECURE_TRANSPORT: set this to true. This indicates that you're doing local testing, and it's OK to use HTTP instead of HTTPS for OAuth. You should only do this for local testing. Do not set this in production!
* ONEAUTH_ALLOWED_PROVIDERS=facebook,google
* ONEAUTH_FACEBOOK_CLIENT_ID: set this to the client ID you got from GitHub.
* ONEAUTH_FACEBOOK_CLIENT_SECRET: set this to the client secret you got from GitHub.

This repository has a .env.example file that you can copy to .env to get a head start.


### step 4: Generate migrations


```shell

# add a migrations folder to your application.
flask db init

# generate an initial migration
flask db migrate -m "Initial migration."

# apply the changes described by the migration script 
flask db upgrade
```

## Models

Following default, customisable database backed models are accessible 
under the `oneauth` key, via the app's extensions list `app.extensions`:

* user model: 
  - `current_app.extensions["oneauth"].user_model` 
  - custom model: `ONEAUTH_USER_MODEL`
* JWT token: 
  - `app.extensions["oneauth"].jwt_model`
  - custom model: `ONEAUTH_JWT_TOKEN_MODEL`
* JWT token: 
  - `app.extensions["oneauth"].oauth_model`
  - custom model: `ONEAUTH_OAUTH_TOKEN_MODEL`
  - associated env variables: 
    - `ONEAUTH_ALLOWED_PROVIDERS` of type list. 
      eg. `ONEAUTH_ALLOWED_PROVIDERS=facebook,google`


## RESTful Endpoints

`oneauth.init_app(app)` in your project's app factory exposes following RESTful API endpoints: 


* `/auth/register` -> registers a new user 

    `username` is E164 mobile number.

    ```shell
    curl -X POST http://localhost:5101/api/auth/register \
        -H "Content-Type: application/json" \
        -d '{"mobile_number":"+221785373740", "password":"19Eddu82!"}'
    ```
    
    ```json
    {
      "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzYzNzc5NDcsImlhdCI6MTY3NjM3NzA0Nywic3ViIjoxfQ.mVovsDw0m6THgIMk5QUc2PpVZN-dgZT9jKO2pxS122s", 
      "message": "Successfully registered.", 
      "status": "success"
    }
    ```

* `auth/login` -> sign in an existing user

    ```shell
    curl -X POST http://localhost:5101/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{"mobile_number":"+221785373740", "password":"19Eddu82!"}'
    ```
    ```json
    {
      "data": {
        "is_admin": false, 
        "mobile_number": "+221785373740", 
        "registered_on": "Tue, 14 Feb 2023 18:23:52 GMT", 
        "user_id": 1
      }, 
      "status": "success"
    }
    ```

* `auth/me` -> get the auth status

    ```shell
    curl http://localhost:5101/auth/me \
        -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzYzOTk5MzIsImlhdCI6MTY3NjM5OTAzMiwic3ViIjoxfQ.TMYgqEc3ws_djVVuUtAqId44KrBAXztA3DAfNrM8bxE"
    ```

* `/auth/logout` -> logs the user out 


## TODO

- OAuth2 via Google, Facebook, Twitter, Telegram?
- login: authenticate user to flask after checking user/pass, before returning token?
- register user page in newsboard client
- serve WSGI in production. Options:
  - [Gunicorn](https://flask.palletsprojects.com/tutorial/deploy/)
  - [waitress](https://stackoverflow.com/a/54381386)
  - [](https://stackoverflow.com/a/74061823)
