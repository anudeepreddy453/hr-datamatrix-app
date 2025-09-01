from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime

with app.app_context():
    # Delete all users
    User.query.delete()
    db.session.commit()
    
    # Create user
    user = User(
        name='Test Admin',
        email='admin@test.com',
        password_hash=generate_password_hash('admin123'),
        role='admin',
        department='IT',
        status='active',
        created_at=datetime.utcnow(),
        approved_at=datetime.utcnow()
    )
    
    db.session.add(user)
    db.session.commit()
    print("✅ User created")
    
    # Test password
    test_user = User.query.filter_by(email='admin@test.com').first()
    if test_user:
        result = test_user.check_password('admin123')
        print(f"✅ Password test: {result}")
        if result:
            print("🎉 SUCCESS! Login should work now!")
        else:
            print("❌ Still failing - need to check app.py")
    else:
        print("❌ User not found")
