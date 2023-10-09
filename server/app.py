#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get("username")
        password = json.get("password")
        image_url = json.get("image_url")
        bio = json.get("bio")

        user = User(
            username=username,
            password_hash=password,
            image_url=image_url,
            bio=bio,
        )

        if user.validate_username(username, user.username):
            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id

            response = make_response(
                user.to_dict(),
                201,
            )

            return response
        else:
            return {}, 422


class CheckSession(Resource):
    def get(self):
        if session["user_id"]:
            user = User.query.get(session["user_id"])

            return make_response(
                user.to_dict(),
                200,
            )
        else:
            return {}, 401


class Login(Resource):
    def post(self):
        json = request.get_json()

        username = json.get("username")
        password = json.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return user.to_dict(), 201
        else:
            return {}, 401


class Logout(Resource):
    def delete(self):
        if session["user_id"]:
            session["user_id"] = None
            return {}, 204
        else:
            return {}, 401


class RecipeIndex(Resource):
    def get(self):
        if session["user_id"]:
            return [
                recipe.to_dict()
                for recipe in Recipe.query.filter_by(user_id=session["user_id"]).all()
            ], 200
        else:
            return {}, 401

    def post(self):
        if not session.get("user_id"):
            return {"error": "Unauthorized"}, 401

        json_data = request.get_json()

        # Validate title
        title = Recipe.validate_title(None, "title", json_data.get("title"))
        if title is None:
            return {"error": "Title is required"}, 422

        # Validate instructions
        instructions = Recipe.validate_instructions(
            None, "instructions", json_data.get("instructions")
        )
        if instructions is None:
            return {"error": "Instructions must be at least 50 characters long."}, 422

        minutes_to_complete = json_data["minutes_to_complete"]

        # Create and save the recipe
        user_id = session["user_id"]
        recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=user_id,
        )

        db.session.add(recipe)
        db.session.commit()

        return recipe.to_dict(), 201


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
