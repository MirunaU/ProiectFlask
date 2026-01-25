from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort
from functools import wraps
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import os
import random

# --- IMPORT MODELS ---
# We import the 'db' variable and the Classes from our models.py file
from models import db, User, Product, Transaction

# --- CONFIGURATION (The Setup) ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'my-secret-key-restaurant-2026' # Change this for production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///restaurant.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- INITIALIZE EXTENSIONS ---
# Connect the database to this specific Flask app
db.init_app(app)

# Setup Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect here if user is not logged in

@login_manager.user_loader
def load_user(user_id):
    # This function is used by Flask-Login to get the current user from the DB
    return User.query.get(int(user_id))


# --- CUSTOM DECORATORS ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificam daca userul e logat si daca e admin
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home')) # Sau poti folosi abort(403)
        return f(*args, **kwargs)
    return decorated_function


# --- ROUTES (The Controller Logic) ---

# Route 1: Home Page
@app.route('/')
def home():
    # 1. TIME-BASED GREETING LOGIC
    # We get the current hour from the server
    from datetime import datetime
    current_hour = datetime.now().hour
    
    if 5 <= current_hour < 12:
        greeting_msg = "Good Morning"
    elif 12 <= current_hour < 18:
        greeting_msg = "Good Afternoon"
    else:
        greeting_msg = "Good Evening"

    # 2. RANDOM PRODUCT LOGIC
    # Fetch all products and pick one randomly
    all_products = Product.query.all()
    featured_item = random.choice(all_products) if all_products else None

    # Render the new home.html template and pass the data
    return render_template('home.html', greeting=greeting_msg, featured_product=featured_item)

# Route 2: Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If the user clicks the "Login" button (POST request)
    if request.method == 'POST':
        username_from_form = request.form.get('username')
        password_from_form = request.form.get('password')

        # Find the user in the database
        user = User.query.filter_by(username=username_from_form).first()

        # Check if user exists and password matches
        # NOTE: In a real app, use password hashing (bcrypt) here
        if user and user.password == password_from_form:
            login_user(user) # Flask remembers the user is logged in
            flash('Login successful!', 'success')
            
            # Redirect admin to dashboard (future) or home
            if user.role == 'admin':
                return redirect(url_for('home'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password!', 'danger')

    # If GET request, just show the login form
    return render_template('login.html')

# Route 3: Logout
@app.route('/logout')
@login_required # Requires user to be logged in to access this
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Route 4: Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If the user fills the form and clicks "Register" (POST)
    if request.method == 'POST':
        username_from_form = request.form.get('username')
        password_from_form = request.form.get('password')

        # Check if username already exists in the database
        existing_user = User.query.filter_by(username=username_from_form).first()

        if existing_user:
            flash('Username already exists! Please choose another one.', 'danger')
            return redirect(url_for('register'))
        
        # Create a new user (default role is 'user', points start at 0)
        new_user = User(username=username_from_form, password=password_from_form, role='user', points=0)
        
        # Save to database
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    # If GET request, show the form
    return render_template('register.html')


# --- ADMIN ROUTES ---

# Route 5: Admin Dashboard (View Products + Users)
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    all_products = Product.query.all()
    all_users = User.query.filter_by(role='user').all() 
    
    return render_template('admin.html', products=all_products, users=all_users)

# Route 6: Add Product (Action)
@app.route('/admin/add', methods=['POST'])
@login_required
@admin_required
def add_product():
    # Get data from the form inputs
    name = request.form.get('name')
    desc = request.form.get('description')
    price = request.form.get('points_cost')
    img = request.form.get('image_url')

    # Create new Product object
    new_item = Product(name=name, description=desc, points_cost=price, image_url=img)
    
    # Save to DB
    db.session.add(new_item)
    db.session.commit()

    flash(f'Product "{name}" added successfully!', 'success')
    return redirect(url_for('admin_panel'))

# Route 7: Delete Product (Action)
@app.route('/admin/delete/<int:product_id>')
@login_required
@admin_required
def delete_product(product_id):
    # Find product by ID
    item_to_delete = Product.query.get(product_id)
    
    if item_to_delete:
        db.session.delete(item_to_delete)
        db.session.commit()
        flash('Product deleted.', 'warning')
    
    return redirect(url_for('admin_panel'))


# --- SHOP ROUTES ---

# Route 8: The Menu (Shop) - WITH SEARCH BAR
@app.route('/menu')
@login_required
def menu():
    # 1. Get the search term from the URL (request.args)
    # Example: If URL is /menu?q=cappuccino, then search_term = "cappuccino"
    search_term = request.args.get('q')

    if search_term:
        # 2. FILTER LOGIC: Search for product names containing the term
        # 'ilike' makes it case-insensitive (so 'Coffee' matches 'coffee')
        all_products = Product.query.filter(Product.name.ilike(f'%{search_term}%')).all()
        
        # Optional: Show a message with how many results were found
        if not all_products:
            flash(f'No items found matching "{search_term}".', 'warning')
        else:
            flash(f'Found {len(all_products)} results for "{search_term}".', 'info')
            
    else:
        # 3. No search term? Show ALL products as usual
        all_products = Product.query.all()
        
    return render_template('shop.html', products=all_products)

# Route 9: Buy Item (Transaction Logic)
@app.route('/buy/<int:product_id>')
@login_required
def buy_product(product_id):
    # 1. Find the product
    item = Product.query.get(product_id)
    
    if not item:
        flash('Product not found.', 'danger')
        return redirect(url_for('menu'))

    # 2. Check if user has enough points
    if current_user.points >= item.points_cost:
        # 3. DEDUCT POINTS
        current_user.points -= item.points_cost
        
        # 4. CREATE TRANSACTION RECORD (History)
        new_trans = Transaction(amount=-item.points_cost, description=f"Redeemed: {item.name}", owner=current_user)
        db.session.add(new_trans)
        
        # 5. SAVE CHANGES
        db.session.commit()
        
        flash(f'Successfully redeemed {item.name}! Enjoy.', 'success')
    else:
        flash('Not enough points!', 'danger')
        
    return redirect(url_for('menu'))


# Route 10: Give Points to User (Admin Action)
@app.route('/admin/give-points', methods=['POST'])
@login_required
@admin_required
def give_points():
    # Luam datele din formular
    user_id = request.form.get('user_id')
    points = request.form.get('points')
    reason = request.form.get('reason')

    # Gasim userul
    user = User.query.get(user_id)
    
    if user:
        # 1. Ii dam punctele
        points_int = int(points)
        user.points += points_int
        
        # 2. Cream tranzactia (istoric)
        new_trans = Transaction(amount=points_int, description=f"Admin Reward: {reason}", owner=user)
        db.session.add(new_trans)
        
        # 3. Salvam
        db.session.commit()
        flash(f'Sent {points} points to {user.username}!', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('admin_panel'))

# Route 11: Transaction History Page
@app.route('/history')
@login_required
def history():
    # Get all transactions for the CURRENT user, ordered by newest first
    my_transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).all()
    
    return render_template('history.html', transactions=my_transactions)

# --- ERROR HANDLERS ---

# Custom 404 Page (Page Not Found)
@app.errorhandler(404)
def page_not_found(e):
    # We pass the error 'e' but we don't use it in the template
    # Note: We return the template and the 404 status code
    return render_template('404.html'), 404

# Custom 500 Page (Internal Server Error) - Optional but good practice
@app.errorhandler(500)
def internal_server_error(e):
    return "<h1>500 - Server Error</h1><p>Something went wrong on our end.</p>", 500

# --- API ROUTES (Pentru aplicatii mobile / externe) ---

@app.route('/api/products')
def api_products():
    products = Product.query.all()
    
    products_list = []
    for item in products:
        products_list.append({
            'id': item.id,
            'name': item.name,
            'price': item.points_cost,
            'description': item.description,
            'image': item.image_url
        })
    
    # 3. Return JSON (not HTML)
    return jsonify({
        'status': 'success',
        'count': len(products_list),
        'data': products_list
    })

# --- SERVER STARTUP & DATABASE SEEDING ---
if __name__ == '__main__':
    with app.app_context():
        # Create 'instance' folder if it doesn't exist
        if not os.path.exists('instance'):
            os.makedirs('instance')
        
        # Create tables based on models.py
        db.create_all()
        
        # --- SEED DATA: Create an Admin if none exists ---
        if not User.query.filter_by(username='admin').first():
            # Creating a default admin: user='admin', pass='123'
            admin_user = User(username='admin', password='123', role='admin', points=9999)
            db.session.add(admin_user)
            db.session.commit()
            print("Default 'admin' user created successfully!")
            
    # Run the server in debug mode
    app.run(debug=True)