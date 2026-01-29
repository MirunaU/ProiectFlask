from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

# Initialize the database variable
db = SQLAlchemy()

# --- 1. USER MODEL (Trebuie sa fie primul!) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user') # 'admin' or 'user'
    points = db.Column(db.Integer, default=0)
    
    # Relationship: One User has Many Transactions
    transactions = db.relationship('Transaction', backref='owner', lazy=True)

# --- 2. PRODUCT MODEL ---
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    points_cost = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(500))

# --- 3. TRANSACTION MODEL (Trebuie sa fie ultimul!) ---
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer, nullable=False) # Negative for spending, Positive for earning
    description = db.Column(db.String(200), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Coloana noua pentru validare
    status = db.Column(db.String(20), default='Completed') # 'Pending' or 'Completed'

    # Foreign Key: Links to the User table
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)