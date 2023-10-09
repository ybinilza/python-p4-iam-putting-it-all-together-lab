from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
from config import db, bcrypt
from sqlalchemy import UniqueConstraint
from sqlalchemy.exc import IntegrityError


class User(db.Model, SerializerMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship("Recipe", backref="user", lazy=True)

    serialize_rules = ("-recipes",)

    def __repr__(self):
        return f"User {self.username}, ID: {self.id}"

    @property
    def password_hash(self):
        raise AttributeError("Password is not accessible")

    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode("utf-8"))

    @validates("username")
    def validate_username(self, key, value):
        if value == "":
            raise ValueError("Username is required")
        return value


class Recipe(db.Model, SerializerMixin):
    __tablename__ = "recipes"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    @validates("title")
    def validate_title(self, key, title):
        if not title:
            raise ValueError("Title is required")
        else:
            return title

    @validates("instruction")
    def validate_instructions(self, key, instructions):
        if len(instructions) <= 50:
            return None
        else:
            return instructions