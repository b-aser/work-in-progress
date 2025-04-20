from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from flask_bcrypt import Bcrypt
import bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from dotenv import load_dotenv
# import PyPDF2
# from io import BytesIO
# from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
# import torch



# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# MySQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@"
    f"{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
)
# app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
#     'pool_pre_ping': True,
#     'pool_recycle': 3600,
#     'pool_size': 10,
#     'max_overflow': 5
# }
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BCRYPT_LOG_ROUNDS'] = 12  # Default is 12, higher is more secure but slower

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Database Models
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    profile_image = db.Column(db.String(255), nullable=True)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=False)
    
    # Relationships
    documents = db.relationship('UserDocument', backref='owner', lazy=True, cascade='all, delete-orphan')
    chats = db.relationship('ChatHistory', backref='user', lazy=True, cascade='all, delete-orphan')
    
class UserDocument(db.Model):
    __tablename__ = 'user_documents'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    uploaded_date = db.Column(db.DateTime, default=datetime.utcnow)
    file_size = db.Column(db.Integer) # in bytes
    page_count = db.Column(db.Integer)  
    processed_text = db.Column(db.Text)

    # Relationships
    chats = db.relationship('ChatHistory', backref='document', lazy=True, cascade='all, delete-orphan')
class ChatHistory(db.Model):
    __tablename__ = 'chat_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    user_document_id = db.Column(db.Integer, db.ForeignKey('user_documents.id', ondelete='CASCADE'), nullable=False)
    user_message = db.Column(db.Text, nullable=False)
    ai_response = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_summary = db.Column(db.Boolean, default=False)
    tokens_used = db.Column(db.Integer)

with app.app_context():
    db.create_all()











# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Authentication routes
@app.route('/register', methods=['GET', 'POST'])  
def register():
    
    if request.method == 'POST':
        fullname = request.form.get('fullname','').strip()
        username = request.form.get('username','').strip()
        email = request.form.get('email','').strip()
        password = request.form.get('password','').strip()
        
        
               
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        # hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            new_user = User(
                username=username, 
                password=password, 
                fullname=fullname, 
                email=email
                )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successfully! Please log in', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')
            flash(app.logger.error(f'Registration error: {str(e)}'))

        
    
    return render_template('register.html')


@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])  
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip()
        input_password = request.form.get('password','').strip()
        
        user = User.query.filter_by(email=email).first()
        
        
        if user:
            try:
                
                
                # Check password
                if  input_password == user.password: # bcrypt.checkpw(input_password.encode('utf-8'), user.password):
                    # Password match - login successful
                    login_user(user)
                    user.last_login = datetime.utcnow()
                    db.session.commit()
                    flash('Login successful', 'success')
                    return redirect(url_for('home'))
                
                else:
                    
                    flash('Invalid password.', 'danger')
                    # flash(app.logger.error(f'Invalid password: {str(user.email)}'))
            except Exception as e:
                db.session.rollback()
                flash('Login failed. Please try again.', 'danger')
                flash(app.logger.error(f'Login error: {str(e)}'))

        else:
            # User not found
            flash('Invalid username or password', 'danger')
            
        
        # if user and bcrypt.checkpw(password.encode('utf-8'), hashed_password) or bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        #     login_user(user)
        #     user.last_login = datetime.utcnow()
        #     db.session.commit()
        #     flash('Login successful', 'success')
        #     return redirect(url_for('dashboard'))
        # else:
        #     flash('Invalid email or password', 'danger')
    return render_template('login.html')







@app.route('/home')
# @login_required
def home():
    return render_template('home.html')

@app.route('/profile')
# @login_required
def profile():
    return render_template('profile.html')

if __name__ == '__main__':
    app.run(debug=True)