"""
JWT Auth using pyjwt
https://jwt.io/introduction/
"""
from flask import Blueprint, request, make_response, jsonify, current_app
from flask.views import MethodView
from flask_login import login_required, current_user

from demo import bcrypt, db
from flask_oneauth.exceptions import exc_msg


User = current_app.extensions["oneauth"].user_model
BlacklistToken = current_app.extensions["oneauth"].jwt_model


__all__ = (
    "jwt_bp",
    "RegisterAPI", "LoginAPI", "LogoutAPI",
    "UserAPI"
)

jwt_bp = Blueprint('auth', __name__)


class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            user, created = User.get_or_create(
                mobile_number=post_data.get('mobile_number'),
                defaults=dict(
                    password=post_data.get('password'),
                    email=post_data.get('email'),
                )
            )

            if user:
                if created:
                    auth_token = user.create_jwt_token(user.id)
                    response = {
                        'status': 'success',
                        'message': 'Successfully registered.',
                        'auth_token': auth_token}
                    return make_response(jsonify(response)), 201

                response = {
                    'status': 'fail',
                    'message': 'User already exists. Please Log in.', }
                return make_response(jsonify(response)), 202

        except Exception as e:
            response = {
                'status': 'fail',
                'message': exc_msg(e)}
            return make_response(jsonify(response)), 401


class LoginAPI(MethodView):
    """
    User Login Resource.
    Login is where user exchanges their username/password for a JWT token.
    Token is used to authenticate subsequent requests.
    """

    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            # fetch the user data
            user = User.get(post_data.get('mobile_number'))
            if user and bcrypt.check_password_hash(
                    user.password, post_data.get('password')
            ):
                auth_token = user.create_jwt_token(user.id)
                if auth_token:
                    response = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token
                    }
                    return make_response(jsonify(response)), 200
            else:
                response = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(response)), 404
        except Exception as e:
            print(e)
            response = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(response)), 500


class UserAPI(MethodView):
    """
    User Resource
    """

    decorators = [login_required, ]

    def get(self):

        response = {
            'status': 'success',
            'data': {
                'user_id': current_user.id,
                'mobile_number': current_user.mobile_number.e164,
                'is_admin': current_user.is_admin,
                'registered_on': current_user.created}
        }
        return make_response(jsonify(response)), 200


class LogoutAPI(MethodView):
    """
    Logout Resource
    """

    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_jwt_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    response = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(response)), 200
                except Exception as e:
                    response = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(response)), 200
            else:
                response = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(response)), 401
        else:
            response = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(response)), 403


# define the API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')

# add Rules for API Endpoints
jwt_bp.add_url_rule('/register', view_func=registration_view, methods=['POST'])
jwt_bp.add_url_rule('/login', view_func=login_view, methods=['POST'])
jwt_bp.add_url_rule('/me', view_func=user_view, methods=['GET'])
jwt_bp.add_url_rule('/logout', view_func=logout_view, methods=['POST'])
