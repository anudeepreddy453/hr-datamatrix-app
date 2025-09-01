#!/usr/bin/env python3
"""
Debug login issues - check user status and credentials
"""

from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime

def debug_users():
    """Debug all users in the database"""
    print("🔍 Debugging Users in Database...")
    print("=" * 60)
    
    with app.app_context():
        users = User.query.all()
        
        if not users:
            print("❌ No users found in database!")
            return
        
        print(f"📊 Found {len(users)} users:")
        print("-" * 60)
        
        for user in users:
            print(f"👤 User: {user.name}")
            print(f"   Email: {user.email}")
            print(f"   Role: {user.role}")
            print(f"   Department: {user.department}")
            print(f"   Status: {user.status}")
            print(f"   Created: {user.created_at}")
            print(f"   Approved: {user.approved_at}")
            print(f"   Password Hash: {user.password_hash[:20]}..." if user.password_hash else "   Password Hash: None")
            
            # Test password verification
            try:
                # Test with common passwords
                test_passwords = ['admin123', 'Admin123!', 'test123', 'Test@123']
                password_works = False
                working_password = None
                
                for pwd in test_passwords:
                    if user.check_password(pwd):
                        password_works = True
                        working_password = pwd
                        break
                
                if password_works:
                    print(f"   ✅ Password works: {working_password}")
                else:
                    print(f"   ❌ No working password found")
                    
            except Exception as e:
                print(f"   ❌ Password check error: {e}")
            
            print("-" * 60)

def fix_user_status():
    """Fix user status to active"""
    print("\n🔧 Fixing User Status...")
    print("=" * 60)
    
    with app.app_context():
        users = User.query.all()
        fixed_count = 0
        
        for user in users:
            if user.status != 'active':
                old_status = user.status
                user.status = 'active'
                user.approved_at = datetime.utcnow()
                fixed_count += 1
                print(f"✅ Fixed {user.email}: {old_status} -> active")
        
        if fixed_count > 0:
            db.session.commit()
            print(f"\n🎉 Fixed {fixed_count} users!")
        else:
            print("ℹ️  All users already have active status")

def create_test_user():
    """Create a guaranteed working test user"""
    print("\n👤 Creating Test User...")
    print("=" * 60)
    
    with app.app_context():
        # Delete existing test user
        existing = User.query.filter_by(email='test@login.com').first()
        if existing:
            db.session.delete(existing)
            db.session.commit()
            print("🗑️  Removed existing test user")
        
        # Create new test user
        user = User(
            name='Test Login User',
            email='test@login.com',
            password_hash=generate_password_hash('test123'),
            role='admin',
            department='IT',
            status='active',
            created_at=datetime.utcnow(),
            approved_at=datetime.utcnow()
        )
        
        db.session.add(user)
        db.session.commit()
        
        print("✅ Test user created:")
        print("   Email: test@login.com")
        print("   Password: test123")
        print("   Role: admin")
        print("   Status: active")

def test_login_logic():
    """Test the login logic manually"""
    print("\n🧪 Testing Login Logic...")
    print("=" * 60)
    
    with app.app_context():
        test_credentials = [
            {'email': 'test@login.com', 'password': 'test123'},
            {'email': 'admin@company.com', 'password': 'Admin123!'}
        ]
        
        for creds in test_credentials:
            print(f"\n🔍 Testing: {creds['email']}")
            
            # Find user
            user = User.query.filter_by(email=creds['email']).first()
            if not user:
                print(f"   ❌ User not found")
                continue
            
            print(f"   ✅ User found: {user.name}")
            print(f"   Status: {user.status}")
            
            # Check password
            if user.check_password(creds['password']):
                print(f"   ✅ Password correct")
                
                # Check status
                if user.status == 'pending':
                    print(f"   ❌ Login would fail: Account pending approval")
                elif user.status == 'rejected':
                    print(f"   ❌ Login would fail: Account rejected")
                elif user.status == 'active':
                    print(f"   ✅ Login would succeed!")
                else:
                    print(f"   ❌ Login would fail: Unknown status '{user.status}'")
            else:
                print(f"   ❌ Password incorrect")

def main():
    """Main debug function"""
    print("🚀 HR DataMatrix Login Debug")
    print("=" * 60)
    
    # Debug users
    debug_users()
    
    # Fix user status
    fix_user_status()
    
    # Create test user
    create_test_user()
    
    # Test login logic
    test_login_logic()
    
    print("\n🎉 Debug Complete!")
    print("=" * 60)
    print("Try logging in with:")
    print("Email: test@login.com")
    print("Password: test123")

if __name__ == "__main__":
    main()
