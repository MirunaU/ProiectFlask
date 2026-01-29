from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort
from functools import wraps
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import os
import random
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from logging.handlers import RotatingFileHandler

# --- IMPORT MODELS ---
# We import the 'db' variable and the Classes from our models.py file
from models import db, User, Product, Transaction

# --- CONFIGURATION (The Setup) ---
app = Flask(__name__)
# --- LOGGING CONFIGURATION ---
# 'restaurant.log' remembers last 10.000 events
if not app.debug:
    pass

file_handler = RotatingFileHandler('restaurant.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)

app.logger.setLevel(logging.INFO)
app.logger.info('Restaurant Rewards Startup')
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
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
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

# Route 2: Login Page (SECURED)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_from_form = request.form.get('username')
        password_from_form = request.form.get('password')

        user = User.query.filter_by(username=username_from_form).first()

        # --- SECURITY UPDATE: Use check_password_hash ---
        if user and check_password_hash(user.password, password_from_form):
            login_user(user)
            # LOGGING:
            app.logger.info(f'Successful login for user: {user.username}')
            flash('Login successful!', 'success')
            
            if user.role == 'admin':
                return redirect(url_for('home'))
            else:
                return redirect(url_for('home'))
        else:
            # LOGGING: 
            app.logger.warning(f'Failed login attempt for username: {username_from_form}')
            flash('Invalid username or password!', 'danger')

    return render_template('login.html')

# Route 3: Logout
@app.route('/logout')
@login_required # Requires user to be logged in to access this
def logout():
    # LOGGING: 
    app.logger.info(f'User {current_user.username} logged out.')

    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Route 4: Register Page (SECURED)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username_from_form = request.form.get('username')
        password_from_form = request.form.get('password')

        # Check if username exists
        existing_user = User.query.filter_by(username=username_from_form).first()

        if existing_user:
            flash('Username already exists! Please choose another one.', 'danger')
            return redirect(url_for('register'))
        
        # --- SECURITY UPDATE: Hash the password ---
        hashed_password = generate_password_hash(password_from_form, method='pbkdf2:sha256')
        
        # Save the HASH, not the plain password
        new_user = User(username=username_from_form, password=hashed_password, role='user', points=0)
        
        db.session.add(new_user)
        db.session.commit()

        # LOGGING:
        app.logger.info(f'New user registered: {username_from_form}')

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# --- ADMIN ROUTES ---

# Route 5: Main Admin Dashboard (Hub)
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    return render_template('dashboard.html')

# Route 5.1: Manage Products Page
@app.route('/admin/products')
@login_required
@admin_required
def admin_products():
    all_products = Product.query.all()
    return render_template('admin.html', products=all_products)

# Route 5.2: Manage Users Page
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    # Excludem adminul din lista ca sa nu ne stergem singuri din greseala
    all_users = User.query.all()
    return render_template('manage_users.html', users=all_users)


# Route 6: Add Product
@app.route('/admin/products/add', methods=['POST'])
@login_required
@admin_required
def add_product():
    name = request.form.get('name')
    desc = request.form.get('description')
    price = request.form.get('points_cost')
    img = request.form.get('image_url')

    new_item = Product(name=name, description=desc, points_cost=price, image_url=img)
    db.session.add(new_item)
    db.session.commit()
    
    app.logger.info(f'Admin added new product: {name}')
    flash(f'Product "{name}" added successfully!', 'success')
    return redirect(url_for('admin_products'))

# Route 7: Delete Product
@app.route('/admin/products/delete/<int:product_id>')
@login_required
@admin_required
def delete_product(product_id):
    item_to_delete = Product.query.get(product_id)
    if item_to_delete:
        name = item_to_delete.name
        db.session.delete(item_to_delete)
        db.session.commit()
        app.logger.warning(f'Admin deleted product: {name}')
        flash('Product deleted.', 'warning')
    return redirect(url_for('admin_products'))


# Route 7.5: EDIT Product 
@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_product(product_id):
    product = Product.query.get(product_id)
    
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('admin_products'))

    if request.method == 'POST':
        # 1. Luam datele noi din formular
        product.name = request.form.get('name')
        product.description = request.form.get('description')
        product.points_cost = int(request.form.get('points_cost'))
        product.image_url = request.form.get('image_url')
        
        # 2. Salvam modificarile (SQL Update)
        db.session.commit()
        
        app.logger.info(f'Admin edited product ID {product.id}: {product.name}')
        flash(f'Updated {product.name} successfully!', 'success')
        return redirect(url_for('admin_products'))

    # Daca e GET, afisam formularul de editare
    return render_template('edit_product.html', product=product)

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
        new_trans = Transaction(
    amount=-item.points_cost, 
    description=f"Redeemed: {item.name}", 
    owner=current_user,
    status='Pending' 
)
        db.session.add(new_trans)
        
        # 5. SAVE CHANGES
        db.session.commit()
        
        # LOGGING:
        app.logger.info(f'Transaction: {current_user.username} bought {item.name} for {item.points_cost} points.')
        flash(f'Successfully redeemed {item.name}! Enjoy.', 'success')
    else:
        flash('Not enough points!', 'danger')
        
    return redirect(url_for('menu'))


# Route 10: Give Points (Moved to User Management)
@app.route('/admin/users/give-points', methods=['POST'])
@login_required
@admin_required
def give_points():
    user_id = request.form.get('user_id')
    points = request.form.get('points')
    reason = request.form.get('reason')

    user = User.query.get(user_id)
    if user:
        points_int = int(points)
        user.points += points_int
        
        new_trans = Transaction(amount=points_int, description=f"Admin Reward: {reason}", owner=user)
        db.session.add(new_trans)
        db.session.commit()
        
        app.logger.info(f'Admin gave {points} points to user {user.username}.')
        flash(f'Sent {points} points to {user.username}!', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('admin_users'))

# Route 10.5: Delete User 
@app.route('/admin/users/delete/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    # Protectie: Nu lasam adminul sa se stearga pe el insusi
    if user_id == current_user.id:
        flash('You cannot delete yourself!', 'danger')
        return redirect(url_for('admin_users'))
        
    user_to_delete = User.query.get(user_id)
    if user_to_delete:
        if user_to_delete.username == 'admin':
             flash('Cannot delete the main admin account.', 'danger')
             return redirect(url_for('admin_users'))
             
        username = user_to_delete.username
        db.session.delete(user_to_delete)
        db.session.commit()
        
        app.logger.warning(f'Admin deleted user: {username}')
        flash(f'User {username} has been deleted.', 'warning')
    
    return redirect(url_for('admin_users'))


# Route 10.7: Admin Reset Password (Manual)
@app.route('/admin/users/reset-password/<int:user_id>')
@login_required
@admin_required
def reset_password(user_id):
    user = User.query.get(user_id)
    
    if user:
        # Protectie: Nu resetam adminul
        if user.username == 'admin':
            flash('Cannot reset admin password here.', 'danger')
            return redirect(url_for('admin_users'))
            
        # Setam parola default "123456"
        default_pass = '123456'
        user.password = generate_password_hash(default_pass, method='pbkdf2:sha256')
        db.session.commit()
        
        app.logger.info(f'Admin forced password reset for user: {user.username}')
        flash(f'Password for {user.username} reset to "{default_pass}".', 'warning')
        
    return redirect(url_for('admin_users'))


# Route 10.8: View Specific User History (The Spy Feature)
@app.route('/admin/users/history/<int:user_id>')
@login_required
@admin_required
def view_user_history(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Luam tranzactiile userului respectiv
    user_trans = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.date.desc()).all()
    
    return render_template('user_history.html', user=user, transactions=user_trans)


# Route 10.9: Validate Order (Mark as Served)
@app.route('/admin/transactions/validate/<int:trans_id>')
@login_required
@admin_required
def validate_order(trans_id):
    trans = Transaction.query.get(trans_id)
    
    if trans:
        if trans.status == 'Pending':
            trans.status = 'Completed'
            db.session.commit()
            app.logger.info(f'Admin validated order #{trans.id} for user {trans.owner.username}')
            flash('Order marked as SERVED! ', 'success')
        else:
            flash('Order is already completed.', 'info')
            
        # Ne intoarcem la pagina de istoric a acelui user
        return redirect(url_for('view_user_history', user_id=trans.user_id))
    
    return redirect(url_for('admin_dashboard'))

# Route 11: Transaction History Page
@app.route('/history')
@login_required
def history():
    # Get all transactions for the CURRENT user, ordered by newest first
    my_transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).all()
    
    return render_template('history.html', transactions=my_transactions)

# Route 12: User Profile (Update Logic - SECURED)
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_pass = request.form.get('new_password')
        
        if new_pass:
            # --- SECURITY UPDATE: Hash the new password ---
            current_user.password = generate_password_hash(new_pass, method='pbkdf2:sha256')
            
            db.session.commit()

            # LOGGING:
            app.logger.info(f'User {current_user.username} changed their password.')

            flash('Password updated successfully!', 'success')
        else:
            flash('Password cannot be empty.', 'warning')
            
        return redirect(url_for('profile'))

    return render_template('profile.html')

# --- ERROR HANDLERS ---

# Custom 404 Page (Page Not Found)
@app.errorhandler(404)
def page_not_found(e):
    # We pass the error 'e' but we don't use it in the template
    # Note: We return the template and the 404 status code
    return render_template('404.html'), 404

# Custom 403 Page (Forbidden / Access Denied)
@app.errorhandler(403)
def forbidden_error(e):
    app.logger.warning(f'Security Alert: User {current_user.username} tried to access Admin Panel!')
    return render_template('403.html'), 403

# Custom 500 Page (Internal Server Error) - Optional but good practice
@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f'Server Error: {e}')
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
        if not os.path.exists('instance'):
            os.makedirs('instance')
        
        db.create_all()
        
        # --- SEED DATA: Create an Admin (SECURED) ---
        if not User.query.filter_by(username='admin').first():
            # Hash the admin password '123'
            hashed_admin_pass = generate_password_hash('123', method='pbkdf2:sha256')
            
            admin_user = User(username='admin', password=hashed_admin_pass, role='admin', points=9999)
            db.session.add(admin_user)
            db.session.commit()
            print("Default 'admin' user created successfully (Secured)!")
            
    app.run(debug=True)