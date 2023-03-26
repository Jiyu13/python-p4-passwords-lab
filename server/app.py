#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204
api.add_resource(ClearSession, '/clear', endpoint='clear')


# where the user enters their username, password, and password confirmation.
class Signup(Resource):
    def post(self):
        username = request.get_json()["username"]
        password = request.get_json()["password"]

        if username and password:
            # create a new user; save their hashed password in the database;
            new_user = User(
                username=username,
            )
            new_user.password_hash = password
            
            db.session.add(new_user)
            db.session.commit()
            # save the user's ID in the session object
            session['user_id'] = new_user.id
            return new_user.to_dict(), 201
        
        return {"error": "422: Unprocessable Content"}, 422
api.add_resource(Signup, '/signup', endpoint="signup")


class CheckSession(Resource):
    def get(self):
        if session.get("user_id"):
            user = User.query.filter(User.id==session["user_id"]).first()
            return user.to_dict(), 200
        return {}, 204
    
api.add_resource(CheckSession, '/check_session', endpoint="check_session")


# where the user submits their username and password and are then logged in.
class Login(Resource):
    def post(self):
        username = request.get_json()["username"]
        password = request.get_json()["password"]

        user = User.query.filter_by(username=username).first()
        if user.authenticate(password):
            session["user_id"] = user.id
            return user.to_dict(), 200
        
        return {'error': '401 Unauthorized'}, 401 
api.add_resource(Login, '/login', endpoint='login')


class Logout(Resource):
    def delete(self):

        session["user_id"] = None
        return {}, 204
api.add_resource(Logout, '/logout', endpoint="logout")



if __name__ == '__main__':
    app.run(port=5555, debug=True)
