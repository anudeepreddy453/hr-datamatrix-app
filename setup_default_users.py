#!/usr/bin/env python3
"""
Setup script to create default users for HR DataMatrix application
Run this script to populate the database with default users
"""

from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime

def create_default_users():
    """Create all default users with their credentials"""
    
    # Default users data from the repository
    default_users = [
        {
            "name": "Priya Sharma",
            "email": "priya.sharma@ccr.com",
            "password": "Priya@123",
            "role": "admin",
            "department": "CCR",
            "status": "active"
        },
        {
            "name": "Rohan Mehta",
            "email": "rohan.mehta@i2r.com",
            "password": "Rohan@123",
            "role": "admin",
            "department": "I2R",
            "status": "active"
        },
        {
            "name": "Anjali Verma",
            "email": "anjali.verma@mkd.com",
            "password": "Anjali@123",
            "role": "admin",
            "department": "MKD",
            "status": "active"
        },
        {
            "name": "Vikram Rao",
            "email": "vikram.rao@bacardi.com",
            "password": "Vikram@123",
            "role": "admin",
            "department": "Bacardi",
            "status": "active"
        },
        {
            "name": "Sneha Kapoor",
            "email": "sneha.kapoor@xone.com",
            "password": "Sneha@123",
            "role": "admin",
            "department": "Xone",
            "status": "active"
        },
        {
            "name": "Arjun Malhotra",
            "email": "arjun.malhotra@cis.com",
            "password": "Arjun@123",
            "role": "admin",
            "department": "CIS",
            "status": "active"
        },
        {
            "name": "Neha Singh",
            "email": "neha.singh@dir.com",
            "password": "Neha@123",
            "role": "admin",
            "department": "DIR",
            "status": "active"
        },
        {
            "name": "Karan Patel",
            "email": "karan.patel@cqis.com",
            "password": "Karan@123",
            "role": "admin",
            "department": "CQIS",
            "status": "active"
        },
        {
            "name": "Meera Nair",
            "email": "meera.nair@osd.com",
            "password": "Meera@123",
            "role": "admin",
            "department": "OSD",
            "status": "active"
        },
        {
            "name": "Suresh Reddy",
            "email": "suresh.reddy@dat.com",
            "password": "Suresh@123",
            "role": "admin",
            "department": "DAT",
            "status": "active"
        },
        {
            "name": "Aditi Joshi",
            "email": "aditi.joshi@dlf.com",
            "password": "Aditi@123",
            "role": "admin",
            "department": "DLF",
            "status": "active"
        },
        {
            "name": "Kavya Menon",
            "email": "kavya.menon@riskweb.com",
            "password": "Kavya@123",
            "role": "admin",
            "department": "Riskweb",
            "status": "active"
        },
        # Additional HR users
        {
            "name": "Amit Patel",
            "email": "amit.patel@ccr.com",
            "password": "Amit@123",
            "role": "hr_manager",
            "department": "CCR",
            "status": "active"
        },
        {
            "name": "Test User",
            "email": "test@example.com",
            "password": "Test@123",
            "role": "user",
            "department": "IT",
            "status": "active"
        }
    ]
    
    with app.app_context():
        # Create database tables
        db.create_all()
        print("✅ Database tables created successfully!")
        
        # Check if users already exist
        existing_users = User.query.all()
        if existing_users:
            print(f"⚠️  Found {len(existing_users)} existing users:")
            for user in existing_users:
                print(f"   - {user.email} ({user.role})")
            
            response = input("\nDo you want to add default users anyway? (y/n): ")
            if response.lower() != 'y':
                print("❌ Setup cancelled.")
                return
        
        # Create default users
        created_count = 0
        for user_data in default_users:
            # Check if user already exists
            existing_user = User.query.filter_by(email=user_data['email']).first()
            if existing_user:
                print(f"⚠️  User {user_data['email']} already exists, skipping...")
                continue
            
            # Create new user
            new_user = User(
                name=user_data['name'],
                email=user_data['email'],
                password_hash=generate_password_hash(user_data['password']),
                role=user_data['role'],
                department=user_data['department'],
                status=user_data['status'],
                created_at=datetime.utcnow(),
                approved_at=datetime.utcnow() if user_data['status'] == 'active' else None
            )
            
            db.session.add(new_user)
            created_count += 1
            print(f"✅ Created user: {user_data['email']} ({user_data['role']})")
        
        # Commit all changes
        db.session.commit()
        
        print(f"\n🎉 Successfully created {created_count} new users!")
        print("\n📋 Default Login Credentials:")
        print("=" * 50)
        
        for user_data in default_users:
            print(f"Email: {user_data['email']}")
            print(f"Password: {user_data['password']}")
            print(f"Role: {user_data['role']}")
            print(f"Department: {user_data['department']}")
            print("-" * 30)
        
        print("\n🚀 You can now login with any of these credentials!")
        print("Frontend URL: http://localhost:3000")
        print("Backend URL: http://localhost:5001")

if __name__ == "__main__":
    print("🔧 Setting up default users for HR DataMatrix...")
    print("=" * 50)
    create_default_users()
