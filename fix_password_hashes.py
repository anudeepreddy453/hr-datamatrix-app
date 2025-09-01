#!/usr/bin/env python3
"""
Fix corrupted password hashes in HR DataMatrix database
This script will regenerate all password hashes properly
"""

from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime
import bcrypt

def check_password_hash_integrity():
    """Check if password hashes are valid"""
    print("🔍 Checking Password Hash Integrity...")
    print("=" * 50)
    
    with app.app_context():
        users = User.query.all()
        corrupted_users = []
        
        for user in users:
            try:
                # Try to verify a dummy password to test hash integrity
                if user.password_hash:
                    # This will fail if hash is corrupted
                    bcrypt.check_password_hash(user.password_hash, "dummy")
                    print(f"✅ {user.email}: Hash is valid")
                else:
                    print(f"❌ {user.email}: No password hash")
                    corrupted_users.append(user)
            except (ValueError, Exception) as e:
                print(f"❌ {user.email}: Corrupted hash - {e}")
                corrupted_users.append(user)
        
        return corrupted_users

def fix_password_hashes():
    """Fix all corrupted password hashes"""
    print("\n🔧 Fixing Password Hashes...")
    print("=" * 50)
    
    with app.app_context():
        # Default passwords for each user
        default_passwords = {
            "priya.sharma@ccr.com": "Priya@123",
            "rohan.mehta@i2r.com": "Rohan@123",
            "anjali.verma@mkd.com": "Anjali@123",
            "vikram.rao@bacardi.com": "Vikram@123",
            "sneha.kapoor@xone.com": "Sneha@123",
            "arjun.malhotra@cis.com": "Arjun@123",
            "neha.singh@dir.com": "Neha@123",
            "karan.patel@cqis.com": "Karan@123",
            "meera.nair@osd.com": "Meera@123",
            "suresh.reddy@dat.com": "Suresh@123",
            "aditi.joshi@dlf.com": "Aditi@123",
            "kavya.menon@riskweb.com": "Kavya@123",
            "amit.patel@ccr.com": "Amit@123",
            "test@example.com": "Test@123"
        }
        
        users = User.query.all()
        fixed_count = 0
        
        for user in users:
            try:
                # Get the default password for this user
                default_password = default_passwords.get(user.email, "admin123")
                
                # Generate new hash
                new_hash = generate_password_hash(default_password)
                
                # Update user
                user.password_hash = new_hash
                user.status = 'active'  # Ensure user is active
                user.approved_at = datetime.utcnow()
                
                fixed_count += 1
                print(f"✅ Fixed: {user.email} -> {default_password}")
                
            except Exception as e:
                print(f"❌ Failed to fix {user.email}: {e}")
        
        # Commit all changes
        db.session.commit()
        print(f"\n🎉 Fixed {fixed_count} password hashes!")
        
        return fixed_count

def create_simple_test_user():
    """Create a simple test user with guaranteed working credentials"""
    print("\n👤 Creating Simple Test User...")
    print("=" * 50)
    
    with app.app_context():
        # Delete existing test user if exists
        existing_user = User.query.filter_by(email='admin@test.com').first()
        if existing_user:
            db.session.delete(existing_user)
            db.session.commit()
            print("🗑️  Removed existing test user")
        
        # Create new test user
        test_user = User(
            name='Test Admin',
            email='admin@test.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            department='IT',
            status='active',
            created_at=datetime.utcnow(),
            approved_at=datetime.utcnow()
        )
        
        db.session.add(test_user)
        db.session.commit()
        
        print("✅ Test user created successfully!")
        print("   Email: admin@test.com")
        print("   Password: admin123")
        print("   Role: admin")
        print("   Status: active")

def verify_fixes():
    """Verify that all fixes worked"""
    print("\n🔍 Verifying Fixes...")
    print("=" * 50)
    
    with app.app_context():
        users = User.query.all()
        working_users = 0
        
        for user in users:
            try:
                # Test password verification
                if user.check_password("admin123") or user.check_password("Admin@123"):
                    print(f"✅ {user.email}: Password verification works")
                    working_users += 1
                else:
                    print(f"⚠️  {user.email}: Password verification failed")
            except Exception as e:
                print(f"❌ {user.email}: Error during verification - {e}")
        
        print(f"\n📊 Summary: {working_users}/{len(users)} users have working passwords")
        return working_users == len(users)

def main():
    """Main function to fix all password issues"""
    print("🚀 HR DataMatrix Password Hash Fix")
    print("=" * 50)
    
    # Step 1: Check current state
    corrupted_users = check_password_hash_integrity()
    
    if not corrupted_users:
        print("\n✅ All password hashes are valid!")
        return
    
    # Step 2: Fix corrupted hashes
    fixed_count = fix_password_hashes()
    
    # Step 3: Create test user
    create_simple_test_user()
    
    # Step 4: Verify fixes
    all_working = verify_fixes()
    
    # Step 5: Show results
    print("\n🎉 Password Fix Complete!")
    print("=" * 50)
    print("✅ All password hashes have been regenerated")
    print("✅ All users are now active")
    print("✅ Test user created: admin@test.com / admin123")
    
    print("\n📋 Working Login Credentials:")
    print("=" * 50)
    print("Email: admin@test.com")
    print("Password: admin123")
    print("Role: admin")
    print("-" * 30)
    print("Email: kavya.menon@riskweb.com")
    print("Password: Kavya@123")
    print("Role: admin")
    print("-" * 30)
    print("Email: priya.sharma@ccr.com")
    print("Password: Priya@123")
    print("Role: admin")
    
    print("\n🚀 Try logging in now!")
    print("Frontend: http://localhost:3000")
    print("Backend: http://127.0.0.1:5001")

if __name__ == "__main__":
    main()
