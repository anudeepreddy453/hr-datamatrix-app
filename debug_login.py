#!/usr/bin/env python3
"""
Simple Login Test - Different Approach
"""

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Create simple Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'test-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_login.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Simple User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), default='active')

def create_test_user():
    """Create a test user"""
    with app.app_context():
        # Delete existing database
        db.drop_all()
        db.create_all()
        
        # Create user
        user = User(
            email='admin@test.com',
            password_hash=generate_password_hash('admin123'),
            status='active'
        )
        
        db.session.add(user)
        db.session.commit()
        print("✅ User created: admin@test.com / admin123")
        
        # Test password
        test_user = User.query.filter_by(email='admin@test.com').first()
        if test_user:
            result = check_password_hash(test_user.password_hash, 'admin123')
            print(f"✅ Password test: {result}")
            if result:
                print("🎉 SUCCESS! This approach works!")
                return True
            else:
                print("❌ Still failing")
                return False
        else:
            print("❌ User not found")
            return False

if __name__ == "__main__":
    create_test_user()
