from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import pandas as pd
import json
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email_config import get_email_config, is_email_configured

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///hr_succession.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-here')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_IDENTITY_CLAIM'] = 'sub'
app.config['JWT_ERROR_MESSAGE_KEY'] = 'message'

db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Fix CORS configuration
CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:3000"], 
     supports_credentials=True, 
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "Access-Control-Allow-Origin"])

# Add CORS headers to all responses
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# JWT Error Handler
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print("🔴 JWT Token Expired")
    return jsonify({
        'message': 'The token has expired',
        'error': 'token_expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    print(f"�� JWT Invalid Token: {error}")
    return jsonify({
        'message': 'Signature verification failed',
        'error': 'invalid_token'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    print(f"🔴 JWT Unauthorized: {error}")
    return jsonify({
        'message': 'Request does not contain an access token',
        'error': 'authorization_required'
    }), 401

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # admin, hr_manager, user
    department = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, approved, rejected, active
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Define relationship with audit logs to handle deletion properly
    audit_logs = db.relationship('AuditLog', backref='user_ref', cascade='all, delete-orphan')
    
    # Define relationship with access requests to handle deletion properly
    access_requests = db.relationship('AccessRequest', foreign_keys='AccessRequest.user_id', cascade='all, delete-orphan')
    
    # Self-referencing relationship for approval
    approver = db.relationship('User', remote_side=[id], backref='approved_users')
    
    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)
        print(f"�� Password set for {self.email}")
    
    def check_password(self, password):
        from werkzeug.security import check_password_hash
        try:
            result = check_password_hash(self.password_hash, password)
            print(f"�� Password check for {self.email}: {result}")
            return result
        except Exception as e:
            print(f"❌ Password check error for {self.email}: {e}")
            return False

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    level = db.Column(db.String(20), nullable=True)  # N-1, N-2, N-3, etc. (optional)
    department = db.Column(db.String(50), nullable=False)
    business_line = db.Column(db.String(50), nullable=False)
    criticality = db.Column(db.String(20), nullable=False)  # High, Medium, Low
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SuccessionPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    incumbent_name = db.Column(db.String(100), nullable=False)
    incumbent_employee_id = db.Column(db.String(50), nullable=False)
    incumbent_tenure = db.Column(db.Integer, nullable=False)  # in months
    retirement_date = db.Column(db.Date, nullable=True)
    readiness_level = db.Column(db.String(20), nullable=False)  # Ready Now, 1-2 years, 3-5 years
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    succession_plan_id = db.Column(db.Integer, db.ForeignKey('succession_plan.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    employee_id = db.Column(db.String(50), nullable=False)
    current_role = db.Column(db.String(100), nullable=False)
    experience_years = db.Column(db.Float, nullable=False)
    readiness_score = db.Column(db.Integer, nullable=False)  # 1-10
    development_plan = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class HistoricalData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)  # Succession, Promotion, Transfer
    from_employee = db.Column(db.String(100), nullable=True)
    to_employee = db.Column(db.String(100), nullable=True)
    action_date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AccessRequest(db.Model):
    """Access request management for new user registrations"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    requested_role = db.Column(db.String(20), nullable=False, default='user')
    request_reason = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, approved, rejected
    hr_approver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    rejected_at = db.Column(db.DateTime, nullable=True)
    rejection_reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    hr_approver = db.relationship('User', foreign_keys=[hr_approver_id], backref='approved_access_requests')

class AuditLog(db.Model):
    """Audit trail for tracking all system changes"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user_name = db.Column(db.String(100), nullable=False)  # Store name at time of action
    user_email = db.Column(db.String(120), nullable=False)  # Store email at time of action
    action = db.Column(db.String(50), nullable=False)  # CREATE, UPDATE, DELETE
    table_name = db.Column(db.String(50), nullable=False)  # users, roles, succession_plans, etc.
    record_id = db.Column(db.Integer, nullable=True)  # ID of the affected record
    old_values = db.Column(db.Text, nullable=True)  # JSON string of old values
    new_values = db.Column(db.Text, nullable=True)  # JSON string of new values
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    user_agent = db.Column(db.Text, nullable=True)  # Browser/client info
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    additional_info = db.Column(db.Text, nullable=True)  # Any additional context

class PasswordReset(db.Model):
    """Password reset tokens for forgotten passwords"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='password_resets')

# ---------- Utilities ----------
def _parse_optional_date(date_str):
    if date_str in (None, "", "null"):
        return None
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return None

def _log_audit(user_id, user_name, user_email, action, table_name, record_id=None, old_values=None, new_values=None, ip_address=None, user_agent=None, additional_info=None):
    """Log audit trail entry"""
    try:
        audit_entry = AuditLog(
            user_id=user_id,
            user_name=user_name,
            user_email=user_email,
            action=action,
            table_name=table_name,
            record_id=record_id,
            old_values=json.dumps(old_values) if old_values else None,
            new_values=json.dumps(new_values) if new_values else None,
            ip_address=ip_address,
            user_agent=user_agent,
            additional_info=additional_info
        )
        db.session.add(audit_entry)
        db.session.commit()
    except Exception as e:
        print(f"Audit logging error: {e}")

def _send_email(to_email, subject, body):
    """Send email using configured SMTP settings"""
    if not is_email_configured():
        print(f"Email not configured. Would send to {to_email}: {subject}")
        return False
    
    try:
        email_config = get_email_config()
        msg = MIMEMultipart()
        msg['From'] = email_config['smtp_username']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
        server.starttls()
        server.login(email_config['smtp_username'], email_config['smtp_password'])
        text = msg.as_string()
        server.sendmail(email_config['smtp_username'], to_email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Email sending error: {e}")
        return False

# Fix SQLAlchemy deprecation warnings
def get_user_by_id(user_id):
    """Get user by ID using session.get() instead of query.get()"""
    return db.session.get(User, user_id)

def get_role_by_id(role_id):
    """Get role by ID using session.get() instead of query.get()"""
    return db.session.get(Role, role_id)

def get_succession_plan_by_id(plan_id):
    """Get succession plan by ID using session.get() instead of query.get()"""
    return db.session.get(SuccessionPlan, plan_id)

def get_access_request_by_id(request_id):
    """Get access request by ID using session.get() instead of query.get()"""
    return db.session.get(AccessRequest, request_id)

# ---------- Routes ----------

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    print("🟢 Health check requested")
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'message': 'HR DataMatrix API is running'
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    print("🟡 Registration request received")
    try:
        data = request.get_json()
        print(f"📝 Registration data: {data}")
        
        # Validate required fields
        required_fields = ['name', 'email', 'password', 'department']
        for field in required_fields:
            if not data.get(field):
                print(f"❌ Missing required field: {field}")
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            print(f"❌ User already exists: {data['email']}")
            return jsonify({'error': 'User with this email already exists'}), 400
        
        # Create new user
        user = User(
            name=data['name'],
            email=data['email'],
            department=data['department'],
            role=data.get('role', 'user'),
            status='pending'  # New users start as pending
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        print(f"✅ User registered: {user.email}")
        
        # Log audit trail
        _log_audit(
            user_id=user.id,
            user_name=user.name,
            user_email=user.email,
            action='CREATE',
            table_name='users',
            record_id=user.id,
            new_values={'name': user.name, 'email': user.email, 'role': user.role, 'department': user.department},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='User registration'
        )
        
        # Send notification email to HR
        hr_users = User.query.filter_by(role='hr_manager').all()
        for hr_user in hr_users:
            _send_email(
                hr_user.email,
                'New User Registration Request',
                f'A new user {user.name} ({user.email}) has registered and is awaiting approval.'
            )
        
        return jsonify({
            'message': 'User registered successfully. Awaiting approval.',
            'user_id': user.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Registration error: {e}")
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    print("🟡 Login request received")
    try:
        data = request.get_json()
        print(f"📝 Login data: {data}")
        
        if not data or not data.get('email') or not data.get('password'):
            print("❌ Missing email or password")
            return jsonify({'error': 'Email and password are required'}), 400
        
        email = data['email']
        password = data['password']
        print(f"🔍 Looking for user: {email}")
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            print(f"❌ User not found: {email}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        print(f"✅ User found: {user.name} ({user.email})")
        print(f"📊 User status: {user.status}")
        print(f"📊 User role: {user.role}")
        
        # Check password
        password_check = user.check_password(password)
        print(f"🔍 Password check result: {password_check}")
        
        if not password_check:
            print(f"❌ Password incorrect for: {email}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check user status
        if user.status == 'pending':
            print(f"❌ Account pending approval: {email}")
            return jsonify({'error': 'Account is pending approval'}), 401
        
        if user.status == 'rejected':
            print(f"❌ Account rejected: {email}")
            return jsonify({'error': 'Account has been rejected'}), 401
        
        if user.status != 'active':
            print(f"❌ Account not active: {email} (status: {user.status})")
            return jsonify({'error': 'Account is not active'}), 401
        
        print(f"✅ User status check passed: {email}")
        
        # Create access token - FIX: Convert user.id to string
        access_token = create_access_token(identity=str(user.id))
        print(f"✅ Access token created for: {email}")
        print(f"🔑 Token identity: {user.id} (type: {type(user.id)})")
        
        # Log audit trail
        _log_audit(
            user_id=user.id,
            user_name=user.name,
            user_email=user.email,
            action='LOGIN',
            table_name='users',
            record_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='User login'
        )
        
        response_data = {
            'access_token': access_token,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'department': user.department
            }
        }
        
        print(f"🎉 Login successful for: {email}")
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user information"""
    print("🟡 Get current user request")
    try:
        user_id = get_jwt_identity()
        print(f"🔑 User ID from token: {user_id}")
        
        # Convert string back to integer for database query
        user_id = int(user_id) if user_id else None
        
        user = get_user_by_id(user_id)
        
        if not user:
            print(f"❌ User not found with ID: {user_id}")
            return jsonify({'error': 'User not found'}), 404
        
        print(f"✅ User found: {user.name} ({user.email})")
        
        return jsonify({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'department': user.department,
            'status': user.status
        }), 200
        
    except Exception as e:
        print(f"❌ Get current user error: {e}")
        return jsonify({'error': f'Failed to get user info: {str(e)}'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout"""
    print("🟡 Logout request")
    try:
        user_id = get_jwt_identity()
        # Convert string back to integer
        user_id = int(user_id) if user_id else None
        
        user = get_user_by_id(user_id)
        
        if user:
            print(f"✅ User logging out: {user.name} ({user.email})")
            _log_audit(
                user_id=user.id,
                user_name=user.name,
                user_email=user.email,
                action='LOGOUT',
                table_name='users',
                record_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                additional_info='User logout'
            )
        
        return jsonify({'message': 'Logged out successfully'}), 200
        
    except Exception as e:
        print(f"❌ Logout error: {e}")
        return jsonify({'error': f'Logout failed: {str(e)}'}), 500

@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    """Get all users (admin only)"""
    print("🟡 Get users request")
    try:
        user_id = get_jwt_identity()
        # Convert string back to integer
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized access attempt by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        users = User.query.all()
        users_data = []
        
        for user in users:
            users_data.append({
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'department': user.department,
                'status': user.status,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'approved_at': user.approved_at.isoformat() if user.approved_at else None
            })
        
        print(f"✅ Returning {len(users_data)} users")
        return jsonify(users_data), 200
        
    except Exception as e:
        print(f"❌ Get users error: {e}")
        return jsonify({'error': f'Failed to get users: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """Update user (admin only)"""
    print(f"🟡 Update user request for ID: {user_id}")
    try:
        current_user_id = get_jwt_identity()
        # Convert string back to integer
        current_user_id = int(current_user_id) if current_user_id else None
        
        current_user = get_user_by_id(current_user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized update attempt by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = get_user_by_id(user_id)
        if not user:
            print(f"❌ User not found with ID: {user_id}")
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        print(f"�� Update data: {data}")
        
        # Store old values for audit
        old_values = {
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'department': user.department,
            'status': user.status
        }
        
        # Update fields
        if 'name' in data:
            user.name = data['name']
        if 'email' in data:
            user.email = data['email']
        if 'role' in data:
            user.role = data['role']
        if 'department' in data:
            user.department = data['department']
        if 'status' in data:
            user.status = data['status']
            if data['status'] == 'active':
                user.approved_at = datetime.utcnow()
                user.approved_by = current_user_id
        
        db.session.commit()
        print(f"✅ User updated: {user.email}")
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='UPDATE',
            table_name='users',
            record_id=user.id,
            old_values=old_values,
            new_values={
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'department': user.department,
                'status': user.status
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='User update'
        )
        
        return jsonify({
            'message': 'User updated successfully',
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'department': user.department,
                'status': user.status
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Update user error: {e}")
        return jsonify({'error': f'Failed to update user: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """Delete user (admin only)"""
    print(f"🟡 Delete user request for ID: {user_id}")
    try:
        current_user_id = get_jwt_identity()
        # Convert string back to integer
        current_user_id = int(current_user_id) if current_user_id else None
        
        current_user = get_user_by_id(current_user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized delete attempt by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = get_user_by_id(user_id)
        if not user:
            print(f"❌ User not found with ID: {user_id}")
            return jsonify({'error': 'User not found'}), 404
        
        # Store user info for audit before deletion
        user_info = {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'department': user.department
        }
        
        db.session.delete(user)
        db.session.commit()
        print(f"✅ User deleted: {user_info['email']}")
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='DELETE',
            table_name='users',
            record_id=user_id,
            old_values=user_info,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='User deletion'
        )
        
        return jsonify({'message': 'User deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Delete user error: {e}")
        return jsonify({'error': f'Failed to delete user: {str(e)}'}), 500

@app.route('/api/access-requests', methods=['GET'])
@jwt_required()
def get_access_requests():
    """Get access requests (HR managers and admins only)"""
    print("🟡 Get access requests")
    try:
        user_id = get_jwt_identity()
        # Convert string back to integer
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role not in ['admin', 'hr_manager']:
            print(f"❌ Unauthorized access requests attempt by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        requests = AccessRequest.query.all()
        requests_data = []
        
        for req in requests:
            user = get_user_by_id(req.user_id)
            requests_data.append({
                'id': req.id,
                'user_name': user.name if user else 'Unknown',
                'user_email': user.email if user else 'Unknown',
                'department': req.department,
                'requested_role': req.requested_role,
                'request_reason': req.request_reason,
                'status': req.status,
                'created_at': req.created_at.isoformat() if req.created_at else None,
                'approved_at': req.approved_at.isoformat() if req.approved_at else None
            })
        
        print(f"✅ Returning {len(requests_data)} access requests")
        return jsonify(requests_data), 200
        
    except Exception as e:
        print(f"❌ Get access requests error: {e}")
        return jsonify({'error': f'Failed to get access requests: {str(e)}'}), 500

@app.route('/api/access-requests/stats', methods=['GET'])
@jwt_required()
def get_access_requests_stats():
    """Get access requests statistics"""
    print("🟡 Get access requests stats request")
    try:
        user_id = get_jwt_identity()
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role not in ['admin', 'hr_manager']:
            print(f"❌ Unauthorized access requests stats by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get statistics
        total_requests = AccessRequest.query.count()
        pending_requests = AccessRequest.query.filter_by(status='pending').count()
        approved_requests = AccessRequest.query.filter_by(status='approved').count()
        rejected_requests = AccessRequest.query.filter_by(status='rejected').count()
        
        # Get department distribution
        dept_counts = db.session.query(
            AccessRequest.department, db.func.count(AccessRequest.id)
        ).group_by(AccessRequest.department).all()
        
        # Get role distribution
        role_counts = db.session.query(
            AccessRequest.requested_role, db.func.count(AccessRequest.id)
        ).group_by(AccessRequest.requested_role).all()
        
        return jsonify({
            'total_requests': total_requests,
            'pending_requests': pending_requests,
            'approved_requests': approved_requests,
            'rejected_requests': rejected_requests,
            'department_distribution': [{'department': dept, 'count': count} for dept, count in dept_counts],
            'role_distribution': [{'role': role, 'count': count} for role, count in role_counts]
        }), 200
        
    except Exception as e:
        print(f"❌ Get access requests stats error: {e}")
        return jsonify({'error': f'Failed to get access requests stats: {str(e)}'}), 500

@app.route('/api/access-requests/<int:request_id>', methods=['PUT'])
@jwt_required()
def update_access_request(request_id):
    """Update access request status (HR managers and admins only)"""
    print(f"🟡 Update access request for ID: {request_id}")
    try:
        current_user_id = get_jwt_identity()
        # Convert string back to integer
        current_user_id = int(current_user_id) if current_user_id else None
        
        current_user = get_user_by_id(current_user_id)
        
        if not current_user or current_user.role not in ['admin', 'hr_manager']:
            print(f"❌ Unauthorized access request update by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        access_request = get_access_request_by_id(request_id)
        if not access_request:
            print(f"❌ Access request not found with ID: {request_id}")
            return jsonify({'error': 'Access request not found'}), 404
        
        data = request.get_json()
        print(f"📝 Access request update data: {data}")
        
        if 'status' not in data:
            print("❌ Status not provided in request")
            return jsonify({'error': 'Status is required'}), 400
        
        # Store old values for audit
        old_values = {
            'status': access_request.status,
            'approved_at': access_request.approved_at.isoformat() if access_request.approved_at else None
        }
        
        access_request.status = data['status']
        
        if data['status'] == 'approved':
            access_request.approved_at = datetime.utcnow()
            access_request.hr_approver_id = current_user_id
            
            # Update user status
            user = get_user_by_id(access_request.user_id)
            if user:
                user.status = 'active'
                user.role = access_request.requested_role
                user.approved_at = datetime.utcnow()
                user.approved_by = current_user_id
                
                # Send approval email
                _send_email(
                    user.email,
                    'Access Request Approved',
                    f'Your access request has been approved. You can now login to the system.'
                )
        
        elif data['status'] == 'rejected':
            access_request.rejected_at = datetime.utcnow()
            access_request.rejection_reason = data.get('rejection_reason', '')
            
            # Update user status
            user = get_user_by_id(access_request.user_id)
            if user:
                user.status = 'rejected'
                
                # Send rejection email
                _send_email(
                    user.email,
                    'Access Request Rejected',
                    f'Your access request has been rejected. Reason: {data.get("rejection_reason", "No reason provided")}'
                )
        
        db.session.commit()
        print(f"✅ Access request updated: {request_id}")
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='UPDATE',
            table_name='access_requests',
            record_id=access_request.id,
            old_values=old_values,
            new_values={
                'status': access_request.status,
                'approved_at': access_request.approved_at.isoformat() if access_request.approved_at else None
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='Access request status update'
        )
        
        return jsonify({'message': 'Access request updated successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Update access request error: {e}")
        return jsonify({'error': f'Failed to update access request: {str(e)}'}), 500

@app.route('/api/audit-logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    """Get audit logs (admin only)"""
    print("🟡 Get audit logs request")
    try:
        user_id = get_jwt_identity()
        # Convert string back to integer
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized audit logs access by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
        logs_data = []
        
        for log in logs:
            logs_data.append({
                'id': log.id,
                'user_name': log.user_name,
                'user_email': log.user_email,
                'action': log.action,
                'table_name': log.table_name,
                'record_id': log.record_id,
                'old_values': json.loads(log.old_values) if log.old_values else None,
                'new_values': json.loads(log.new_values) if log.new_values else None,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'additional_info': log.additional_info
            })
        
        print(f"✅ Returning {len(logs_data)} audit logs")
        return jsonify(logs_data), 200
        
    except Exception as e:
        print(f"❌ Get audit logs error: {e}")
        return jsonify({'error': f'Failed to get audit logs: {str(e)}'}), 500

@app.route('/api/audit-trail', methods=['GET'])
@jwt_required()
def get_audit_trail():
    """Get audit trail with pagination and filtering"""
    print("🟡 Get audit trail request")
    try:
        user_id = get_jwt_identity()
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized audit trail access by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        action = request.args.get('action', '')
        table = request.args.get('table', '')
        user = request.args.get('user', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        # Build query
        query = AuditLog.query
        
        if action:
            query = query.filter(AuditLog.action.contains(action))
        if table:
            query = query.filter(AuditLog.table_name.contains(table))
        if user:
            query = query.filter(AuditLog.user_name.contains(user))
        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(AuditLog.timestamp >= date_from_obj)
            except ValueError:
                pass
        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
                query = query.filter(AuditLog.timestamp <= date_to_obj)
            except ValueError:
                pass
        
        # Paginate results
        logs = query.order_by(AuditLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        logs_data = []
        for log in logs.items:
            logs_data.append({
                'id': log.id,
                'user_name': log.user_name,
                'user_email': log.user_email,
                'action': log.action,
                'table_name': log.table_name,
                'record_id': log.record_id,
                'old_values': json.loads(log.old_values) if log.old_values else None,
                'new_values': json.loads(log.new_values) if log.new_values else None,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                'additional_info': log.additional_info
            })
        
        print(f"✅ Returning {len(logs_data)} audit trail entries")
        return jsonify({
            'logs': logs_data,
            'total': logs.total,
            'pages': logs.pages,
            'current_page': page,
            'per_page': per_page
        }), 200
        
    except Exception as e:
        print(f"❌ Get audit trail error: {e}")
        return jsonify({'error': f'Failed to get audit trail: {str(e)}'}), 500

@app.route('/api/audit-trail/summary', methods=['GET'])
@jwt_required()
def get_audit_trail_summary():
    """Get audit trail summary statistics"""
    print("🟡 Get audit trail summary request")
    try:
        user_id = get_jwt_identity()
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized audit trail summary access by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get summary statistics
        total_logs = AuditLog.query.count()
        today_logs = AuditLog.query.filter(
            AuditLog.timestamp >= datetime.utcnow().date()
        ).count()
        
        # Get action distribution
        action_counts = db.session.query(
            AuditLog.action, db.func.count(AuditLog.id)
        ).group_by(AuditLog.action).all()
        
        # Get table distribution
        table_counts = db.session.query(
            AuditLog.table_name, db.func.count(AuditLog.id)
        ).group_by(AuditLog.table_name).all()
        
        # Get user activity
        user_activity = db.session.query(
            AuditLog.user_name, db.func.count(AuditLog.id)
        ).group_by(AuditLog.user_name).order_by(db.func.count(AuditLog.id).desc()).limit(10).all()
        
        return jsonify({
            'total_logs': total_logs,
            'today_logs': today_logs,
            'action_distribution': [{'action': action, 'count': count} for action, count in action_counts],
            'table_distribution': [{'table': table, 'count': count} for table, count in table_counts],
            'user_activity': [{'user': user, 'count': count} for user, count in user_activity]
        }), 200
        
    except Exception as e:
        print(f"❌ Get audit trail summary error: {e}")
        return jsonify({'error': f'Failed to get audit trail summary: {str(e)}'}), 500

@app.route('/api/roles', methods=['GET'])
@jwt_required()
def get_roles():
    """Get all roles"""
    print("🟡 Get roles request")
    try:
        roles = Role.query.all()
        roles_data = []
        
        for role in roles:
            roles_data.append({
                'id': role.id,
                'title': role.title,
                'name': role.name,
                'level': role.level,
                'department': role.department,
                'business_line': role.business_line,
                'criticality': role.criticality,
                'created_at': role.created_at.isoformat() if role.created_at else None
            })
        
        print(f"✅ Returning {len(roles_data)} roles")
        return jsonify(roles_data), 200
        
    except Exception as e:
        print(f"❌ Get roles error: {e}")
        return jsonify({'error': f'Failed to get roles: {str(e)}'}), 500

@app.route('/api/roles', methods=['POST'])
@jwt_required()
def create_role():
    """Create a new role (admin only)"""
    print("🟡 Create role request")
    try:
        user_id = get_jwt_identity()
        # Convert string back to integer
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized role creation by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        print(f"📝 Role creation data: {data}")
        
        # Validate required fields
                # Validate required fields
        required_fields = ['title', 'name', 'department', 'business_line', 'criticality']
        for field in required_fields:
            if not data.get(field):
                print(f"❌ Missing required field: {field}")
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create new role
        role = Role(
            title=data['title'],
            name=data['name'],
            level=data.get('level'),
            department=data['department'],
            business_line=data['business_line'],
            criticality=data['criticality']
        )
        
        db.session.add(role)
        db.session.commit()
        print(f"✅ Role created: {role.title}")
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='CREATE',
            table_name='roles',
            record_id=role.id,
            new_values={
                'title': role.title,
                'name': role.name,
                'level': role.level,
                'department': role.department,
                'business_line': role.business_line,
                'criticality': role.criticality
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='Role creation'
        )
        
        return jsonify({
            'message': 'Role created successfully',
            'role': {
                'id': role.id,
                'title': role.title,
                'name': role.name,
                'level': role.level,
                'department': role.department,
                'business_line': role.business_line,
                'criticality': role.criticality
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Create role error: {e}")
        return jsonify({'error': f'Failed to create role: {str(e)}'}), 500

@app.route('/api/roles/<int:role_id>', methods=['PUT'])
@jwt_required()
def update_role(role_id):
    """Update a role (admin only)"""
    print(f"🟡 Update role request for ID: {role_id}")
    try:
        user_id = get_jwt_identity()
        # Convert string back to integer
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized role update by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        role = get_role_by_id(role_id)
        if not role:
            print(f"❌ Role not found with ID: {role_id}")
            return jsonify({'error': 'Role not found'}), 404
        
        data = request.get_json()
        print(f"📝 Role update data: {data}")
        
        # Store old values for audit
        old_values = {
            'title': role.title,
            'name': role.name,
            'level': role.level,
            'department': role.department,
            'business_line': role.business_line,
            'criticality': role.criticality
        }
        
        # Update fields
        if 'title' in data:
            role.title = data['title']
        if 'name' in data:
            role.name = data['name']
        if 'level' in data:
            role.level = data['level']
        if 'department' in data:
            role.department = data['department']
        if 'business_line' in data:
            role.business_line = data['business_line']
        if 'criticality' in data:
            role.criticality = data['criticality']
        
        db.session.commit()
        print(f"✅ Role updated: {role.title}")
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='UPDATE',
            table_name='roles',
            record_id=role.id,
            old_values=old_values,
            new_values={
                'title': role.title,
                'name': role.name,
                'level': role.level,
                'department': role.department,
                'business_line': role.business_line,
                'criticality': role.criticality
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='Role update'
        )
        
        return jsonify({
            'message': 'Role updated successfully',
            'role': {
                'id': role.id,
                'title': role.title,
                'name': role.name,
                'level': role.level,
                'department': role.department,
                'business_line': role.business_line,
                'criticality': role.criticality
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Update role error: {e}")
        return jsonify({'error': f'Failed to update role: {str(e)}'}), 500

@app.route('/api/roles/<int:role_id>', methods=['DELETE'])
@jwt_required()
def delete_role(role_id):
    """Delete a role (admin only)"""
    print(f"🟡 Delete role request for ID: {role_id}")
    try:
        user_id = get_jwt_identity()
        # Convert string back to integer
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized role deletion by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        role = get_role_by_id(role_id)
        if not role:
            print(f"❌ Role not found with ID: {role_id}")
            return jsonify({'error': 'Role not found'}), 404
        
        # Store role info for audit before deletion
        role_info = {
            'id': role.id,
            'title': role.title,
            'name': role.name,
            'level': role.level,
            'department': role.department,
            'business_line': role.business_line,
            'criticality': role.criticality
        }
        
        db.session.delete(role)
        db.session.commit()
        print(f"✅ Role deleted: {role_info['title']}")
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='DELETE',
            table_name='roles',
            record_id=role_id,
            old_values=role_info,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='Role deletion'
        )
        
        return jsonify({'message': 'Role deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Delete role error: {e}")
        return jsonify({'error': f'Failed to delete role: {str(e)}'}), 500

@app.route('/api/succession-plans', methods=['GET'])
@jwt_required()
def get_succession_plans():
    """Get all succession plans"""
    print("🟡 Get succession plans request")
    try:
        plans = SuccessionPlan.query.all()
        plans_data = []
        
        for plan in plans:
            role = get_role_by_id(plan.role_id)
            plans_data.append({
                'id': plan.id,
                'role_title': role.title if role else 'Unknown',
                'role_name': role.name if role else 'Unknown',
                'incumbent_name': plan.incumbent_name,
                'incumbent_employee_id': plan.incumbent_employee_id,
                'incumbent_tenure': plan.incumbent_tenure,
                'retirement_date': plan.retirement_date.isoformat() if plan.retirement_date else None,
                'readiness_level': plan.readiness_level,
                'created_at': plan.created_at.isoformat() if plan.created_at else None,
                'updated_at': plan.updated_at.isoformat() if plan.updated_at else None
            })
        
        print(f"✅ Returning {len(plans_data)} succession plans")
        return jsonify(plans_data), 200
        
    except Exception as e:
        print(f"❌ Get succession plans error: {e}")
        return jsonify({'error': f'Failed to get succession plans: {str(e)}'}), 500

@app.route('/api/succession-plans', methods=['POST'])
@jwt_required()
def create_succession_plan():
    """Create a new succession plan (admin only)"""
    print("🟡 Create succession plan request")
    try:
        user_id = get_jwt_identity()
        # Convert string back to integer
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized succession plan creation by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        print(f"📝 Succession plan creation data: {data}")
        
        # Validate required fields
        required_fields = ['role_id', 'incumbent_name', 'incumbent_employee_id', 'incumbent_tenure', 'readiness_level']
        for field in required_fields:
            if not data.get(field):
                print(f"❌ Missing required field: {field}")
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validate role exists
        role = get_role_by_id(data['role_id'])
        if not role:
            print(f"❌ Role not found with ID: {data['role_id']}")
            return jsonify({'error': 'Role not found'}), 404
        
        # Create new succession plan
        plan = SuccessionPlan(
            role_id=data['role_id'],
            incumbent_name=data['incumbent_name'],
            incumbent_employee_id=data['incumbent_employee_id'],
            incumbent_tenure=data['incumbent_tenure'],
            retirement_date=_parse_optional_date(data.get('retirement_date')),
            readiness_level=data['readiness_level']
        )
        
        db.session.add(plan)
        db.session.commit()
        print(f"✅ Succession plan created: {plan.incumbent_name}")
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='CREATE',
            table_name='succession_plans',
            record_id=plan.id,
            new_values={
                'role_id': plan.role_id,
                'incumbent_name': plan.incumbent_name,
                'incumbent_employee_id': plan.incumbent_employee_id,
                'incumbent_tenure': plan.incumbent_tenure,
                'retirement_date': plan.retirement_date.isoformat() if plan.retirement_date else None,
                'readiness_level': plan.readiness_level
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='Succession plan creation'
        )
        
        return jsonify({
            'message': 'Succession plan created successfully',
            'plan': {
                'id': plan.id,
                'role_id': plan.role_id,
                'incumbent_name': plan.incumbent_name,
                'incumbent_employee_id': plan.incumbent_employee_id,
                'incumbent_tenure': plan.incumbent_tenure,
                'retirement_date': plan.retirement_date.isoformat() if plan.retirement_date else None,
                'readiness_level': plan.readiness_level
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Create succession plan error: {e}")
        return jsonify({'error': f'Failed to create succession plan: {str(e)}'}), 500

@app.route('/api/succession-plans/<int:plan_id>', methods=['PUT'])
@jwt_required()
def update_succession_plan(plan_id):
    """Update a succession plan (admin only)"""
    print(f"🟡 Update succession plan request for ID: {plan_id}")
    try:
        user_id = get_jwt_identity()
        # Convert string back to integer
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized succession plan update by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        plan = get_succession_plan_by_id(plan_id)
        if not plan:
            print(f"❌ Succession plan not found with ID: {plan_id}")
            return jsonify({'error': 'Succession plan not found'}), 404
        
        data = request.get_json()
        print(f"📝 Succession plan update data: {data}")
        
        # Store old values for audit
        old_values = {
            'role_id': plan.role_id,
            'incumbent_name': plan.incumbent_name,
            'incumbent_employee_id': plan.incumbent_employee_id,
            'incumbent_tenure': plan.incumbent_tenure,
            'retirement_date': plan.retirement_date.isoformat() if plan.retirement_date else None,
            'readiness_level': plan.readiness_level
        }
        
        # Update fields
        if 'role_id' in data:
            plan.role_id = data['role_id']
        if 'incumbent_name' in data:
            plan.incumbent_name = data['incumbent_name']
        if 'incumbent_employee_id' in data:
            plan.incumbent_employee_id = data['incumbent_employee_id']
        if 'incumbent_tenure' in data:
            plan.incumbent_tenure = data['incumbent_tenure']
        if 'retirement_date' in data:
            plan.retirement_date = _parse_optional_date(data['retirement_date'])
        if 'readiness_level' in data:
            plan.readiness_level = data['readiness_level']
        
        db.session.commit()
        print(f"✅ Succession plan updated: {plan.incumbent_name}")
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='UPDATE',
            table_name='succession_plans',
            record_id=plan.id,
            old_values=old_values,
            new_values={
                'role_id': plan.role_id,
                'incumbent_name': plan.incumbent_name,
                'incumbent_employee_id': plan.incumbent_employee_id,
                'incumbent_tenure': plan.incumbent_tenure,
                'retirement_date': plan.retirement_date.isoformat() if plan.retirement_date else None,
                'readiness_level': plan.readiness_level
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='Succession plan update'
        )
        
        return jsonify({
            'message': 'Succession plan updated successfully',
            'plan': {
                'id': plan.id,
                'role_id': plan.role_id,
                'incumbent_name': plan.incumbent_name,
                'incumbent_employee_id': plan.incumbent_employee_id,
                'incumbent_tenure': plan.incumbent_tenure,
                'retirement_date': plan.retirement_date.isoformat() if plan.retirement_date else None,
                'readiness_level': plan.readiness_level
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Update succession plan error: {e}")
        return jsonify({'error': f'Failed to update succession plan: {str(e)}'}), 500

@app.route('/api/succession-plans/<int:plan_id>', methods=['DELETE'])
@jwt_required()
def delete_succession_plan(plan_id):
    """Delete a succession plan (admin only)"""
    print(f"🟡 Delete succession plan request for ID: {plan_id}")
    try:
        user_id = get_jwt_identity()
        # Convert string back to integer
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized succession plan deletion by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        plan = get_succession_plan_by_id(plan_id)
        if not plan:
            print(f"❌ Succession plan not found with ID: {plan_id}")
            return jsonify({'error': 'Succession plan not found'}), 404
        
        # Store plan info for audit before deletion
        plan_info = {
            'id': plan.id,
            'role_id': plan.role_id,
            'incumbent_name': plan.incumbent_name,
            'incumbent_employee_id': plan.incumbent_employee_id,
            'incumbent_tenure': plan.incumbent_tenure,
            'retirement_date': plan.retirement_date.isoformat() if plan.retirement_date else None,
            'readiness_level': plan.readiness_level
        }
        
        db.session.delete(plan)
        db.session.commit()
        print(f"✅ Succession plan deleted: {plan_info['incumbent_name']}")
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='DELETE',
            table_name='succession_plans',
            record_id=plan_id,
            old_values=plan_info,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info='Succession plan deletion'
        )
        
        return jsonify({'message': 'Succession plan deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Delete succession plan error: {e}")
        return jsonify({'error': f'Failed to delete succession plan: {str(e)}'}), 500

@app.route('/api/analytics/demographics', methods=['GET'])
@jwt_required()
def get_demographics_analytics():
    """Get demographics analytics"""
    print("🟡 Get demographics analytics request")
    try:
        user_id = get_jwt_identity()
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized demographics access by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get department demographics
        dept_counts = db.session.query(
            User.department, db.func.count(User.id)
        ).group_by(User.department).all()
        
        # Get role demographics
        role_counts = db.session.query(
            User.role, db.func.count(User.id)
        ).group_by(User.role).all()
        
        # Get status demographics
        status_counts = db.session.query(
            User.status, db.func.count(User.id)
        ).group_by(User.status).all()
        
        # Get user creation trends (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_users = User.query.filter(
            User.created_at >= thirty_days_ago
        ).count()
        
        return jsonify({
            'department_distribution': [{'department': dept, 'count': count} for dept, count in dept_counts],
            'role_distribution': [{'role': role, 'count': count} for role, count in role_counts],
            'status_distribution': [{'status': status, 'count': count} for status, count in status_counts],
            'recent_users_30_days': recent_users
        }), 200
        
    except Exception as e:
        print(f"❌ Get demographics analytics error: {e}")
        return jsonify({'error': f'Failed to get demographics analytics: {str(e)}'}), 500

@app.route('/api/analytics/trends', methods=['GET'])
@jwt_required()
def get_trends_analytics():
    """Get trends analytics"""
    print("🟡 Get trends analytics request")
    try:
        user_id = get_jwt_identity()
        user_id = int(user_id) if user_id else None
        
        current_user = get_user_by_id(user_id)
        
        if not current_user or current_user.role != 'admin':
            print(f"❌ Unauthorized trends access by: {current_user.email if current_user else 'Unknown'}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get user registration trends (last 7 days)
        trends_data = []
        for i in range(7):
            date = datetime.utcnow().date() - timedelta(days=i)
            count = User.query.filter(
                db.func.date(User.created_at) == date
            ).count()
            trends_data.append({
                'date': date.isoformat(),
                'new_users': count
            })
        
        # Get access request trends
        access_trends = []
        for i in range(7):
            date = datetime.utcnow().date() - timedelta(days=i)
            count = AccessRequest.query.filter(
                db.func.date(AccessRequest.created_at) == date
            ).count()
            access_trends.append({
                'date': date.isoformat(),
                'new_requests': count
            })
        
        return jsonify({
            'user_registration_trends': trends_data,
            'access_request_trends': access_trends
        }), 200
        
    except Exception as e:
        print(f"❌ Get trends analytics error: {e}")
        return jsonify({'error': f'Failed to get trends analytics: {str(e)}'}), 500

# Debug endpoints for testing
@app.route('/api/test', methods=['GET'])
def test_endpoint():
    """Test endpoint for debugging"""
    return jsonify({
        'message': 'Backend is working!',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/api/debug/users', methods=['GET'])
def debug_users():
    """Debug endpoint to list all users"""
    try:
        users = User.query.all()
        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'department': user.department,
                'status': user.status,
                'password_hash_length': len(user.password_hash) if user.password_hash else 0
            })
        return jsonify(users_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/password', methods=['POST'])
def debug_password():
    """Debug endpoint to test password verification"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        result = user.check_password(password)
        return jsonify({
            'email': email,
            'password_check': result,
            'user_status': user.status,
            'user_role': user.role
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Create database tables
with app.app_context():
    db.create_all()
    print("✅ Database tables created")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
