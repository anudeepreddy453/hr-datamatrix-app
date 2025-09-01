#!/usr/bin/env python3
"""
Office Laptop Fix - Complete Database Reset
"""

import os
from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime

def reset_database():
    """Reset the database completely"""
    print("�� Resetting Database...")
    
    # Delete database file if it exists
    db_file = 'instance/hr_succession.db'
    if os.path.exists(db_file):
        os.remove(db_file)
        print(f"🗑️  Deleted: {db_file}")
    
    with app.app_context():
        db.create_all()
        print("✅ Created fresh database")

def create_users():
    """Create users with working passwords"""
    print("\n👥 Creating Users...")
    
    with app.app_context():
        users_data = [
            {
                "name": "Admin User",
                "email": "admin@test.com",
                "password": "admin123",
                "role": "admin",
                "department": "IT"
            },
            {
                "name": "Test User",
                "email": "test@test.com",
                "password": "test123", 
                "role": "user",
                "department": "IT"
            },
            {
                "name": "HR Manager",
                "email": "hr@test.com",
                "password": "hr123",
                "role": "hr_manager", 
                "department": "HR"
            }
        ]
        
        for user_data in users_data:
            user = User(
                name=user_data['name'],
                email=user_data['email'],
                password_hash=generate_password_hash(user_data['password']),
                role=user_data['role'],
                department=user_data['department'],
                status='active',
                created_at=datetime.utcnow(),
                approved_at=datetime.utcnow()
            )
            
            db.session.add(user)
            print(f"✅ Created: {user_data['email']} / {user_data['password']}")
        
        db.session.commit()
        print(f"\n🎉 Created {len(users_data)} users!")

def test_users():
    """Test all users work"""
    print("\n🔍 Testing Users...")
    
    with app.app_context():
        users = User.query.all()
        
        password_map = {
            "admin@test.com": "admin123",
            "test@test.com": "test123",
            "hr@test.com": "hr123"
        }
        
        for user in users:
            if user.email in password_map:
                test_password = password_map[user.email]
                result = user.check_password(test_password)
                status = "✅ PASS" if result else "❌ FAIL"
                print(f"{user.email}: {status}")
            else:
                print(f"{user.email}: ⚠️  UNKNOWN")

def main():
    """Main function"""
    print("🚀 Office Laptop Fix")
    print("=" * 50)
    
    # Reset database
    reset_database()
    
    # Create users
    create_users()
    
    # Test users
    test_users()
    
    print("\n📋 Login Credentials:")
    print("=" * 50)
    print("Email: admin@test.com")
    print("Password: admin123")
    print("-" * 30)
    print("Email: test@test.com")
    print("Password: test123")
    print("-" * 30)
    print("Email: hr@test.com")
    print("Password: hr123")
    
    print("\n🚀 Next Steps:")
    print("=" * 50)
    print("1. Restart backend: python app.py")
    print("2. Try logging in with any credential above")
    print("3. This should definitely work now!")

if __name__ == "__main__":
    main()
