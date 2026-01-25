from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

# 1. Create the database instance (we will connect it to the app later)
db = SQLAlchemy()

# --- M V C: The MODELS (Database Tables) ---

# Class 1: User Table
# Handles authentication and points wallet
class User(UserMixin, db.Model):
    __tablename__ = 'users' # Name of the table in SQL
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user') # Can be 'admin' or 'user'
    points = db.Column(db.Integer, default=0) # The digital currency
    
    # Relationship: A user has many transactions
    transactions = db.relationship('Transaction', backref='owner', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

# Class 2: Product Table
# The items available in the Reward Store
class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    points_cost = db.Column(db.Integer, nullable=False) # Price in points
    image_url = db.Column(db.String(500)) # URL to the image on the web

# Class 3: Transaction Table
# History of points earned or spent
class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer, nullable=False) # e.g., +50 or -100
    description = db.Column(db.String(200)) # Reason (e.g., "Bonus", "Purchased Burger")
    date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign Key: Links to the User table
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)