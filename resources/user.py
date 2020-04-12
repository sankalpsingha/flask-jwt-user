from flask_restful import Resource
from flask import request
from werkzeug.security import generate_password_hash, check_password_hash, safe_str_cmp
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_refresh_token_required,
    get_jwt_identity,
    jwt_required,
    get_raw_jwt
)

from models.user import UserModel
from schemas.user import UserSchema
from blacklist import BLACKLIST
# Creating the schema object
user_schema = UserSchema()

class UserRegister(Resource):
    @classmethod
    def post(cls):
        user = user_schema.load(request.get_json())

        if UserModel.find_by_username(user.username):
            return { 'message': 'User already exists.' }, 400
        # Save user if new user
        user.save_to_db()
        return {'message': 'User has been created successfully.'}, 200

class User(Resource):
    @classmethod
    def get(cls, user_id: int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return { 'message': 'The user does not exist'}
        # Return user if the user has been found.
        return user_schema.dump(user),200

    @classmethod
    def delete(cls, user_id: int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return { 'message': 'The user does not exist'}
        user.delete_from_db()
        return { 'message': 'The user has been deleted' }


class UserLogin(Resource):
    @classmethod
    def post(cls):
        user_data = user_schema.load(request.get_json())
        user = UserModel.find_by_username(user_data.username)
        
        if user and safe_str_cmp(user_data.password, user.password):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return { 'access_token': access_token, 'refresh_token': refresh_token}, 200
        
        return {'message': 'The credentials are invalid'}, 401


class UserLogout(Resource):
    @classmethod
    @jwt_required
    def post(cls):
        jti = get_raw_jwt()['jti']
        user_id = get_jwt_identity()
        BLACKLIST.add(jti)
        return { 'message':'The user has logged out' }

class TokenRefresh(Resource):
    @classmethod
    @jwt_refresh_token_required
    def post(cls):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user)
        return {'access_token': new_token}, 200
        