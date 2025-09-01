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
# Explicitly use header-based JWT to avoid CSRF-related 422s
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

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
    return jsonify({
        'message': 'The token has expired',
        'error': 'token_expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'message': 'Signature verification failed',
        'error': 'invalid_token'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
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
    
    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

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

# ---------- Routes ----------

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'message': 'HR DataMatrix API is running'
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'password', 'department']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
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
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not user.check_password(data['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check user status
        if user.status == 'pending':
            return jsonify({'error': 'Account is pending approval'}), 401
        
        if user.status == 'rejected':
            return jsonify({'error': 'Account has been rejected'}), 401
        
        if user.status != 'active':
            return jsonify({'error': 'Account is not active'}), 401
        
        # Create access token
        access_token = create_access_token(identity=user.id)
        
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
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'department': user.department
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user information"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'department': user.department,
            'status': user.status
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get user info: {str(e)}'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user:
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
        return jsonify({'error': f'Logout failed: {str(e)}'}), 500

@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    """Get all users (admin only)"""
    try:
        user_id = get_jwt_identity()
        current_user = User.query.get(user_id)
        
        if not current_user or current_user.role != 'admin':
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
        
        return jsonify(users_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get users: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """Update user (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
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
        return jsonify({'error': f'Failed to update user: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """Delete user (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        user = User.query.get(user_id)
        if not user:
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
        return jsonify({'error': f'Failed to delete user: {str(e)}'}), 500

@app.route('/api/access-requests', methods=['GET'])
@jwt_required()
def get_access_requests():
    """Get access requests (HR managers and admins only)"""
    try:
        user_id = get_jwt_identity()
        current_user = User.query.get(user_id)
        
        if not current_user or current_user.role not in ['admin', 'hr_manager']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        requests = AccessRequest.query.all()
        requests_data = []
        
        for req in requests:
            user = User.query.get(req.user_id)
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
        
        return jsonify(requests_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get access requests: {str(e)}'}), 500

@app.route('/api/access-requests/<int:request_id>', methods=['PUT'])
@jwt_required()
def update_access_request(request_id):
    """Update access request status (HR managers and admins only)"""
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if not current_user or current_user.role not in ['admin', 'hr_manager']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        access_request = AccessRequest.query.get(request_id)
        if not access_request:
            return jsonify({'error': 'Access request not found'}), 404
        
        data = request.get_json()
        
        if 'status' not in data:
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
            user = User.query.get(access_request.user_id)
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
            user = User.query.get(access_request.user_id)
            if user:
                user.status = 'rejected'
                
                # Send rejection email
                _send_email(
                    user.email,
                    'Access Request Rejected',
                    f'Your access request has been rejected. Reason: {data.get("rejection_reason", "No reason provided")}'
                )
        
        db.session.commit()
        
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
        return jsonify({'error': f'Failed to update access request: {str(e)}'}), 500

@app.route('/api/audit-logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    """Get audit logs (admin only)"""
    try:
        user_id = get_jwt_identity()
        current_user = User.query.get(user_id)
        
        if not current_user or current_user.role != 'admin':
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
        
        return jsonify(logs_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get audit logs: {str(e)}'}), 500

@app.route('/api/roles', methods=['GET'])
@jwt_required()
def get_roles():
    """Get all roles"""
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
        
        return jsonify(roles_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get roles: {str(e)}'}), 500

@app.route('/api/roles', methods=['POST'])
@jwt_required()
def create_role():
    """Create a new role (admin only)"""
    try:
        user_id = get_jwt_identity()
        current_user = User.query.get(user_id)
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['title', 'name', 'department', 'business_line', 'criticality']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
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
        return jsonify({'error': f'Failed to create role: {str(e)}'}), 500

@app.route('/api/succession-plans', methods=['GET'])
@jwt_required()
def get_succession_plans():
    """Get all succession plans"""
    try:
        plans = SuccessionPlan.query.all()
        plans_data = []
        
        for plan in plans:
            role = Role.query.get(plan.role_id)
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
        
        return jsonify(plans_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get succession plans: {str(e)}'}), 500

@app.route('/api/succession-plans', methods=['POST'])
@jwt_required()
def create_succession_plan():
    """Create a new succession plan (admin only)"""
    try:
        user_id = get_jwt_identity()
        current_user = User.query.get(user_id)
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['role_id', 'incumbent_name', 'incumbent_employee_id', 'incumbent_tenure', 'readiness_level']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
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
        return jsonify({'error': f'Failed to create succession plan: {str(e)}'}), 500

@app.route('/api/upload-roles', methods=['POST'])
@jwt_required()
def upload_roles():
    """Upload roles from Excel file (admin only)"""
    try:
        user_id = get_jwt_identity()
        current_user = User.query.get(user_id)
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.xlsx'):
            return jsonify({'error': 'Please upload an Excel file (.xlsx)'}), 400
        
        # Read Excel file
        df = pd.read_excel(file)
        
        # Validate required columns
        required_columns = ['Title', 'Name', 'Department', 'Business Line', 'Criticality']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return jsonify({'error': f'Missing required columns: {missing_columns}'}), 400
        
        created_count = 0
        errors = []
        
        for index, row in df.iterrows():
            try:
                role = Role(
                    title=row['Title'],
                    name=row['Name'],
                    level=row.get('Level'),
                    department=row['Department'],
                    business_line=row['Business Line'],
                    criticality=row['Criticality']
                )
                
                db.session.add(role)
                created_count += 1
                
            except Exception as e:
                errors.append(f"Row {index + 1}: {str(e)}")
        
        db.session.commit()
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='CREATE',
            table_name='roles',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info=f'Bulk role upload: {created_count} roles created, {len(errors)} errors'
        )
        
        return jsonify({
            'message': f'Successfully uploaded {created_count} roles',
            'created_count': created_count,
            'errors': errors
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to upload roles: {str(e)}'}), 500

@app.route('/api/upload-succession-plans', methods=['POST'])
@jwt_required()
def upload_succession_plans():
    """Upload succession plans from Excel file (admin only)"""
    try:
        user_id = get_jwt_identity()
        current_user = User.query.get(user_id)
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.xlsx'):
            return jsonify({'error': 'Please upload an Excel file (.xlsx)'}), 400
        
        # Read Excel file
        df = pd.read_excel(file)
        
        # Validate required columns
        required_columns = ['Role Title', 'Incumbent Name', 'Employee ID', 'Tenure (months)', 'Readiness Level']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return jsonify({'error': f'Missing required columns: {missing_columns}'}), 400
        
        created_count = 0
        errors = []
        
        for index, row in df.iterrows():
            try:
                # Find role by title
                role = Role.query.filter_by(title=row['Role Title']).first()
                if not role:
                    errors.append(f"Row {index + 1}: Role '{row['Role Title']}' not found")
                    continue
                
                plan = SuccessionPlan(
                    role_id=role.id,
                    incumbent_name=row['Incumbent Name'],
                    incumbent_employee_id=row['Employee ID'],
                    incumbent_tenure=row['Tenure (months)'],
                    retirement_date=_parse_optional_date(row.get('Retirement Date')),
                    readiness_level=row['Readiness Level']
                )
                
                db.session.add(plan)
                created_count += 1
                
            except Exception as e:
                errors.append(f"Row {index + 1}: {str(e)}")
        
        db.session.commit()
        
        # Log audit trail
        _log_audit(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='CREATE',
            table_name='succession_plans',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            additional_info=f'Bulk succession plan upload: {created_count} plans created, {len(errors)} errors'
        )
        
        return jsonify({
            'message': f'Successfully uploaded {created_count} succession plans',
            'created_count': created_count,
            'errors': errors
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to upload succession plans: {str(e)}'}), 500

@app.route('/api/analytics/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_analytics():
    """Get dashboard analytics (admin only)"""
    try:
        user_id = get_jwt_identity()
        current_user = User.query.get(user_id)
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get counts
        total_users = User.query.count()
        pending_users = User.query.filter_by(status='pending').count()
        active_users = User.query.filter_by(status='active').count()
        total_roles = Role.query.count()
        total_succession_plans = SuccessionPlan.query.count()
        
        # Get department distribution
        department_counts = db.session.query(User.department, db.func.count(User.id)).group_by(User.department).all()
        department_data = [{'department': dept, 'count': count} for dept, count in department_counts]
        
        # Get role distribution
        role_counts = db.session.query(User.role, db.func.count(User.id)).group_by(User.role).all()
        role_data = [{'role': role, 'count': count} for role, count in role_counts]
        
        # Get readiness level distribution
        readiness_counts = db.session.query(SuccessionPlan.readiness_level, db.func.count(SuccessionPlan.id)).group_by(SuccessionPlan.readiness_level).all()
        readiness_data = [{'level': level, 'count': count} for level, count in readiness_counts]
        
        return jsonify({
            'total_users': total_users,
            'pending_users': pending_users,
            'active_users': active_users,
            'total_roles': total_roles,
            'total_succession_plans': total_succession_plans,
            'department_distribution': department_data,
            'role_distribution': role_data,
            'readiness_distribution': readiness_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get analytics: {str(e)}'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5001)
