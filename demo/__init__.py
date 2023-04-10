"""

curl -X POST http://localhost:5000/auth/register
"""
import flask
from flask_bcrypt import Bcrypt
from flask_caching import Cache
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

from flask_oneauth import OneAuth
from flask_oneauth.helpers import get_env


# secret key used for JWT encryption. to generate the secret key,
# run in shell : `SECRET_KEY=$(openssl rand -base64 32)`
SECRET_KEY = get_env('SECRET_KEY')

POSTGRES_DB = get_env("POSTGRES_DB")
POSTGRES_USER = get_env("POSTGRES_USER")
POSTGRES_PASSWORD = get_env("POSTGRES_PASSWORD")


class Config:
    SECRET_KEY = SECRET_KEY
    SQLALCHEMY_DATABASE_URI = \
        "postgresql+psycopg2://{}:{}@localhost:5432/{}"\
        .format(POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB)


db = SQLAlchemy()
bcrypt = Bcrypt()
cache = Cache()
oneauth = OneAuth(db, bcrypt, cache=cache)
migrate = Migrate()


# flask --app demo run --debug
# Flask will automatically detect the factory
# if it is named create_app or make_app
def create_app():

    app = flask.Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    cache.init_app(app)
    oneauth.init_app(app)
    migrate.init_app(app, db)

    print(app.url_map)
    return app



