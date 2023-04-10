from flask import Flask
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_login import LoginManager, current_user

from . import helpers
from .exceptions import ImproperlyConfigured, exc_msg
from .models import get_user_model, get_jwt_token_model
from .models.auth import get_oauth_token_model


# instantiate Flask-Login extension dependency
login_manager = LoginManager()
login_manager.login_view = 'views.login_api'


allowed_providers = helpers.get_env(
    "ONEAUTH_ALLOWED_PROVIDERS", ["facebook", "google"], coerce="list")


# params for registering blueprint with provider
# read field values from the env
# eg. ONEAUTH_GOOGLE_CLIENT_ID, ONEAUTH_GOOGLE_CLIENT_SECRET
get_oauth_app_credentials = lambda provider: \
    {"%s" % field: helpers.get_env("ONEAUTH_%s_%s" % (provider.upper(), field.upper()))
     for field in ["client_id", "client_secret"]}


class OneAuth:
    """
    Extension that works with Flask-SQLAlchemy to provide
    a User model, RESTFul authentication and CRUD views for user management
    Guidelines: https://flask.palletsprojects.com/en/2.2.x/extensiondev/

    Usage:

        import flask
        from flask_bcrypt import Bcrypt

        # the db, bcrypt, and flask_oneauth extensions instances below exists independently of the application.
        # This means that other modules in a user’s project can do  `from project import db, bcrypt, flask_oneauth`,
        # and use the extension in blueprints before the app exists.

        db = SQLAlchemy()
        bcrypt = Bcrypt()
        oneauth = OneAuth(db, bcrypt)

        # This allows the extension to support the application factory pattern,
        # avoids circular import issues when importing the extension instance elsewhere in a user’s code,
        # and makes testing with different configurations easier.

        def create_app():

            app = flask.Flask(__name__)
            db.init_app(app)
            bcrypt.init_app(app)
            oneauth.init_app(app)
            ...
            return app


        >>> from flask import current_app
        >>> User = current_app.extensions["oneauth"].user_model
        >>> User.object.get_or_create(...)
    """

    def __init__(self, db, bcrypt, cache=None, app: Flask = None):
        """

        :param db: database engine, eg. Flask-SQLAlchemy
        :param bcrypt:
        :param cache: caching system for the db, so that it is more performant under heavy load.
        :param Optional[Flask] app:
        """

        self.user_model = get_user_model(db, bcrypt)
        self.jwt_model = get_jwt_token_model(db)
        self.oauth_model = get_oauth_token_model(db, self.user_model)

        self.db = db
        self.bcrypt = bcrypt
        self.cache = cache

        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        Apply the extension instance to the given application instance.
        """
        if not app or not isinstance(app, Flask):
            raise TypeError(f"Invalid Flask app instance: {app}")

        # avail user model class to user code.
        app.extensions["oneauth"] = self

        with app.app_context():
            from . import views

            # register jwt blueprint
            login_manager.init_app(app)

            @login_manager.request_loader
            def load_user_from_request(request):
                """
                This sets the callback for loading a user from a Flask request.
                Works with `@login_required` to protect views.
                https://stackoverflow.com/a/54020299
                """
                auth_headers = request.headers.get('Authorization', '').split()
                if len(auth_headers) != 2:
                    return None
                jwt_token = auth_headers[1]
                user_id_or_error = self.user_model.decode_jwt_token(jwt_token)
                if not isinstance(user_id_or_error, str):
                    return self.user_model.query.filter_by(id=user_id_or_error).first()
                return None

            app.register_blueprint(views.jwt_bp, url_prefix='/auth')

            # register available oauth blueprints
            # uses SQLAlchemyStorage to store and retrieve OAuth tokens using the db
            # https://flask-dance.readthedocs.io/en/latest/storages.html
            try:
                oauth_blueprints = [
                    helpers.import_attr(f"flask_dance.contrib.{p}.make_{p}_blueprint")
                    (get_oauth_app_credentials(p)) for p in allowed_providers]

                for bp, provider in zip(oauth_blueprints, allowed_providers):
                    bp.storage = SQLAlchemyStorage(self.oauth_model, self.db.session, user=current_user,
                                                   cache=self.cache, user_required=False)
                    app.register_blueprint(bp, url_prefix=f"/auth")

            except Exception as e:
                raise ImproperlyConfigured(e)
