#!/usr/bin/env python3
"""
Comprehensive test file to diagnose HR DataMatrix connection and authentication issues
Run this script to test all common problems
"""

import requests
import json
from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime

def test_database_connection():
    """Test if database is working and users exist"""
    print("🔍 Testing Database Connection...")
    print("=" * 50)
    
    try:
        with app.app_context():
            # Test database connection
            users = User.query.all()
            print(f"✅ Database connected successfully!")
            print(f"📊 Found {len(users)} users in database:")
            
            if not users:
                print("❌ No users found in database!")
                return False
            
            for user in users:
                print(f"   - {user.email} ({user.role}) - Status: {user.status}")
            
            return True
            
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

def test_backend_server():
    """Test if backend server is responding"""
    print("\n🌐 Testing Backend Server...")
    print("=" * 50)
    
    try:
        # Test basic connection
        response = requests.get("http://127.0.0.1:5001/", timeout=5)
        print(f"✅ Backend server is responding!")
        print(f"   Status Code: {response.status_code}")
        return True
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend server!")
        print("   Make sure backend is running: python app.py")
        return False
        
    except Exception as e:
        print(f"❌ Backend server error: {e}")
        return False

def test_login_api():
    """Test login API with different scenarios"""
    print("\n🔐 Testing Login API...")
    print("=" * 50)
    
    # Test credentials
    test_credentials = [
        {"email": "kavya.menon@riskweb.com", "password": "Kavya@123"},
        {"email": "priya.sharma@ccr.com", "password": "Priya@123"},
        {"email": "admin@test.com", "password": "admin123"},
        {"email": "test@example.com", "password": "Test@123"}
    ]
    
    for creds in test_credentials:
        print(f"\n🧪 Testing: {creds['email']}")
        
        try:
            response = requests.post(
                "http://127.0.0.1:5001/api/auth/login",
                json=creds,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            print(f"   Status Code: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Login successful!")
                print(f"   Token: {data.get('access_token', 'No token')[:20]}...")
                print(f"   User: {data.get('user', {}).get('name', 'Unknown')}")
                return True
                
            elif response.status_code == 401:
                print(f"   ❌ Invalid credentials")
                print(f"   Response: {response.text}")
                
            else:
                print(f"   ❌ Unexpected error: {response.status_code}")
                print(f"   Response: {response.text}")
                
        except Exception as e:
            print(f"   ❌ Request failed: {e}")
    
    return False

def test_user_creation():
    """Create a test user if none exist"""
    print("\n👤 Testing User Creation...")
    print("=" * 50)
    
    try:
        with app.app_context():
            # Check if any users exist
            users = User.query.all()
            
            if not users:
                print("❌ No users found, creating test user...")
                
                # Create test user
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
                
                return True
            else:
                print(f"✅ Users already exist ({len(users)} users)")
                return True
                
    except Exception as e:
        print(f"❌ User creation failed: {e}")
        return False

def test_cors_headers():
    """Test CORS headers"""
    print("\n🌍 Testing CORS Headers...")
    print("=" * 50)
    
    try:
        # Test preflight request
        response = requests.options(
            "http://127.0.0.1:5001/api/auth/login",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type"
            },
            timeout=5
        )
        
        print(f"   Status Code: {response.status_code}")
        print(f"   CORS Headers: {dict(response.headers)}")
        
        if "Access-Control-Allow-Origin" in response.headers:
            print("✅ CORS headers present")
            return True
        else:
            print("❌ CORS headers missing")
            return False
            
    except Exception as e:
        print(f"❌ CORS test failed: {e}")
        return False

def test_password_verification():
    """Test password verification for existing users"""
    print("\n🔑 Testing Password Verification...")
    print("=" * 50)
    
    try:
        with app.app_context():
            users = User.query.all()
            
            for user in users[:3]:  # Test first 3 users
                print(f"\n🧪 Testing user: {user.email}")
                
                # Test with common passwords
                test_passwords = [
                    f"{user.name.split()[0]}@123",  # Name@123 format
                    "admin123",
                    "password123",
                    "test123"
                ]
                
                for password in test_passwords:
                    if user.check_password(password):
                        print(f"   ✅ Password found: {password}")
                        break
                else:
                    print(f"   ❌ No matching password found")
                    
    except Exception as e:
        print(f"❌ Password verification failed: {e}")

def fix_common_issues():
    """Fix common issues automatically"""
    print("\n🔧 Fixing Common Issues...")
    print("=" * 50)
    
    try:
        with app.app_context():
            # Fix 1: Ensure all users have active status
            inactive_users = User.query.filter(User.status != 'active').all()
            if inactive_users:
                print(f"🔧 Activating {len(inactive_users)} inactive users...")
                for user in inactive_users:
                    user.status = 'active'
                    user.approved_at = datetime.utcnow()
                db.session.commit()
                print("✅ Users activated!")
            
            # Fix 2: Create a simple test user
            test_user = User.query.filter_by(email='admin@test.com').first()
            if not test_user:
                print("🔧 Creating simple test user...")
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
                print("✅ Test user created!")
            
            # Fix 3: Verify password hashes
            print("🔧 Verifying password hashes...")
            for user in User.query.all():
                if not user.password_hash or len(user.password_hash) < 10:
                    print(f"   🔧 Fixing password for {user.email}")
                    user.password_hash = generate_password_hash('admin123')
            db.session.commit()
            print("✅ Password hashes verified!")
            
    except Exception as e:
        print(f"❌ Fix failed: {e}")

def main():
    """Run all tests"""
    print("🚀 HR DataMatrix Connection & Authentication Test")
    print("=" * 60)
    
    # Run all tests
    tests = [
        ("Database Connection", test_database_connection),
        ("Backend Server", test_backend_server),
        ("CORS Headers", test_cors_headers),
        ("User Creation", test_user_creation),
        ("Password Verification", test_password_verification),
        ("Login API", test_login_api)
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results[test_name] = False
    
    # Summary
    print("\n📊 Test Results Summary")
    print("=" * 50)
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name}: {status}")
    
    # Fix issues if needed
    if not all(results.values()):
        print("\n🔧 Attempting to fix issues...")
        fix_common_issues()
        
        # Re-test login
        print("\n🔄 Re-testing login after fixes...")
        test_login_api()
    
    # Final recommendations
    print("\n💡 Recommendations:")
    print("=" * 50)
    
    if not results.get("Backend Server", False):
        print("1. Start backend server: python app.py")
    
    if not results.get("Database Connection", False):
        print("2. Check database file exists: hr_succession.db")
    
    if not results.get("Login API", False):
        print("3. Try these test credentials:")
        print("   Email: admin@test.com")
        print("   Password: admin123")
    
    print("4. Check browser console (F12) for errors")
    print("5. Ensure frontend is running on http://localhost:3000")
    print("6. Ensure backend is running on http://127.0.0.1:5001")

if __name__ == "__main__":
    main()
