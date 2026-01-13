from flask import request, session, jsonify
from flask_restful import Resource
from werkzeug.security import generate_password_hash, check_password_hash

from config import app, db, api
from models import User

class ClearSession(Resource):
    def delete(self):
        session.pop('page_views', None)
        session.pop('user_id', None)
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        if not username or not password:
            return {"message": "Username and password are required"}, 400

        if User.query.filter_by(username=username).first():
            return {"message": "User already exists"}, 400

        user = User(username=username)
        user.password_hash = password
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id

        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return '', 204

        user = User.query.get(user_id)
        if not user:
            return '', 204

        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not user.authenticate(password):
            return {"message": "Invalid credentials"}, 401

        session['user_id'] = user.id

        return user.to_dict(), 200

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return {}, 204

# Add resources to the API
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

# Run the app
if __name__ == '__main__':
    app.run(port=5555, debug=True)
