from datetime import datetime

import flask
import jwt
import phonenumbers
from flask import current_app
from flask_bcrypt import Bcrypt
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

from phonenumbers import region_code_for_number, format_number
from sqlalchemy_utils import PhoneNumber

from ..helpers import import_env
from .base import get_base_model


__all__ = (
    "get_user_model", "get_jwt_token_model", "get_oauth_token_model",
    "parse_phone_number",
)


def parse_phone_number(pn: str) -> PhoneNumber:
    if isinstance(pn, PhoneNumber):
        return pn
    pn = phonenumbers.parse(pn)
    return PhoneNumber(str(pn.national_number), region_code_for_number(pn))


def get_user_model(db: SQLAlchemy, bcrypt: Bcrypt):
    """

    :param SQLAlchemy db: SQLAlchemy ext., not bound to app
    :param Bcrypt bcrypt: Bcrypt ext., not bound to app
    :return: default `User` model

    Usage:
        >>> from flask_oneauth.models import get_user_model
        >>> User = get_user_model(db, bcrypt)
        >>> me = User.objects.get(id=XXX)
    """

    base_model = get_base_model(db)

    class User(UserMixin, db.Model, base_model):
        """
        User model where users authenticate with their mobile number.
        """
        __tablename__ = "users"

        id = db.Column(db.Integer, primary_key=True, autoincrement=True)
        created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, onupdate=datetime.utcnow)
        is_admin = db.Column(db.Boolean, nullable=False, default=False)

        # store country_code separately.
        # useful for stats, eg., group users by country, carrier, etc.
        # now on, calling code deals only with the composite key `mobile_number`
        password = db.Column(db.String(255), nullable=False)
        _mobile_number = db.Column(db.Unicode(20), unique=True)
        country_code = db.Column(db.Unicode(8))
        mobile_number = db.composite(PhoneNumber, _mobile_number, country_code)

        # profile data
        name = db.Column(db.String, nullable=False)
        email = db.Column(db.String(255), unique=True)
        avatar_url = db.Column(db.String, nullable=True)

        def __repr__(self):
            return '<User %r>' % self.mobile_number

        def __init__(self, mobile_number, email, password, avatar_url=None, is_admin=False):
            """

            :param mobile_number: required. E164 format, eg. +221785373740
            :param email: optional email
            :param str password: plain pwd. encrypted before saving to db
            :param str avatar_url:
            :param bool is_admin: creates an admin user if True
            """
            self.mobile_number = parse_phone_number(mobile_number)
            self.email = email
            self.password = bcrypt.generate_password_hash(
                password, flask.current_app.config.get('BCRYPT_LOG_ROUNDS')).decode()
            self.created = datetime.datetime.now()
            self.is_admin = is_admin
            self.avatar_url = avatar_url

        @staticmethod
        def get(mobile_number):
            """ Override. Lookup a user by their mobile number. """
            pn = parse_phone_number(mobile_number)
            return User.query.filter_by(mobile_number=pn).first()

        def create_jwt_token(self, user_id) -> str:
            """
            Generates the Auth Token. Uses following JWT claims:
                exp: expiration date of the token
                iat: the time the token is generated
                sub: the subject of the token (the user whom it identifies)
            Requires current_app.config.SECRET_KEY. Generate one by running in shell:
                # >>> SECRET_KEY=$(openssl rand -base64 32)
            """
            try:
                payload = {'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=15),
                           'iat': datetime.datetime.utcnow(), 'sub': user_id}
                return jwt.encode(payload, current_app.config.get('SECRET_KEY'), algorithm='HS256')
            except Exception as e:
                return e

        @staticmethod
        def decode_jwt_token(auth_token) -> int or str:
            """
            Decodes the auth token.
            Returns the user_id (claim's subject) as an integer
            or an indicative failure message (str)

            :param auth_token:
            :return:  - an
            """
            try:
                payload = jwt.decode(auth_token, current_app.config.get('SECRET_KEY'), algorithms=["HS256"])
                is_blacklisted_token = get_jwt_token_model().check_blacklist(auth_token)
                if is_blacklisted_token:
                    return 'Token blacklisted. Please log in again.'
                return payload['sub']
            except jwt.ExpiredSignatureError:
                return 'Signature expired. Please log in again.'
            except jwt.InvalidTokenError:
                return 'Invalid token. Please log in again.'

    user_model = import_env("ONEAUTH_USER_MODEL", User)
    return user_model


def get_jwt_token_model(db: SQLAlchemy):

    class BlacklistToken(db.Model):
        """
        Token Model for storing JWT tokens
        """
        __tablename__ = 'blacklist_tokens'

        id = db.Column(db.Integer, primary_key=True, autoincrement=True)
        token = db.Column(db.String(500), unique=True, nullable=False)
        blacklisted_on = db.Column(db.DateTime, nullable=False)

        def __init__(self, token):
            self.token = token
            self.blacklisted_on = datetime.datetime.now()

        def __repr__(self):
            return '<id: token: {}'.format(self.token)

        @staticmethod
        def check_blacklist(auth_token):
            # check whether auth token has been blacklisted
            res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
            if res:
                return True
            else:
                return False

    model = import_env("ONEAUTH_JWT_TOKEN_MODEL", BlacklistToken)
    return model


def get_oauth_token_model(db: SQLAlchemy, User):
    """
    OAuthToken v2.0
    Multiple oauth providers possible per user!
    """

    class OAuthToken(OAuthConsumerMixin, db.Model):
        user_id = db.Column(db.Integer, db.ForeignKey(User.id))
        user = db.relationship(User)

    model = import_env("ONEAUTH_OAUTH_TOKEN_MODEL", OAuthToken)
    return model
