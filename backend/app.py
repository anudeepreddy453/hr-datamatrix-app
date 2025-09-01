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
CORS(app)

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
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

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
        # Expecting YYYY-MM-DD from HTML date input
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except Exception:
        return None

def _has_hr_access(user_role):
    """Check if user has HR access to view succession plans"""
    hr_roles = ['admin', 'hr_manager', 'HR Manager', 'HR Business Partner', 'Recruitment Specialist', 
                'Talent Acquisition Manager', 'Learning & Development Specialist', 'Compensation & Benefits Analyst',
                'Employee Relations Specialist', 'HR Operations Specialist']
    return user_role in hr_roles

def _validate_password(password):
    """
    Validate password strength:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
    
    return True, "Password is strong"

def _log_audit_trail(user_id, user_name, user_email, action, table_name, record_id=None, 
                     old_values=None, new_values=None, additional_info=None):
    """Log an audit trail entry"""
    try:
        # Get client IP and user agent from request context
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get('User-Agent') if request else None
        
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
        # Log error but don't fail the main operation
        print(f"Audit logging failed: {str(e)}")
        db.session.rollback()


def _generate_reset_token():
    """Generate a secure random token for password reset"""
    return secrets.token_urlsafe(32)


def _send_password_reset_email(user_email, user_name, reset_token):
    """Send password reset email to user"""
    try:
        # Get email configuration
        email_config = get_email_config()
        
        # Check if email is properly configured
        if not is_email_configured():
            print(f"📧 Password reset email would be sent to {user_email}")
            print(f"🔑 Reset token: {reset_token}")
            print(f"🔗 Reset link: http://localhost:3000/reset-password?token={reset_token}")
            print(f"💡 To enable real email sending, update email_config.py with your Gmail credentials")
            return True
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = f"{email_config['from_name']} <{email_config['smtp_username']}>"
        msg['To'] = user_email
        msg['Subject'] = 'Password Reset Request - HR Succession Planning System'
        
        # Email body
        reset_link = f"http://localhost:3000/reset-password?token={reset_token}"
        body = f"""Hello {user_name},

You have requested a password reset for your HR Succession Planning System account.

To reset your password, please click on the following link:
{reset_link}

This link will expire in 1 hour for security reasons.

If you did not request this password reset, please ignore this email.

Best regards,
{email_config['from_name']}"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        # For console-based reset, always return the reset link
        reset_link = f"http://localhost:3000/reset-password?token={reset_token}"
        print(f"📧 Password reset link generated for {user_email}")
        print(f"🔗 Reset link: {reset_link}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to send password reset email: {str(e)}")
        print(f"📧 For now, showing reset link in console:")
        print(f"   Reset link: http://localhost:3000/reset-password?token={reset_token}")
        return True

# Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'HR Succession Planning API is running'})

@app.route('/api/test-auth', methods=['GET'])
@jwt_required()
def test_auth():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    return jsonify({
        'message': 'Authentication successful',
        'user_id': current_user_id,
        'email': current_user.email if current_user else 'Unknown'
    })

@app.route('/api/debug-jwt', methods=['GET'])
def debug_jwt():
    return jsonify({
        'secret_key': app.config['SECRET_KEY'],
        'jwt_secret_key': app.config['JWT_SECRET_KEY'],
        'jwt_config': {
            'token_location': app.config.get('JWT_TOKEN_LOCATION'),
            'header_name': app.config.get('JWT_HEADER_NAME'),
            'header_type': app.config.get('JWT_HEADER_TYPE')
        }
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Check if required fields are present
        if not data or 'name' not in data or 'email' not in data or 'password' not in data or 'department' not in data:
            return jsonify({'error': 'Missing required fields: name, email, password, department'}), 400
        
        # Check if email already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        # Validate password strength
        is_valid, message = _validate_password(data['password'])
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Create user with pending status
        user = User(
            name=data['name'],
            email=data['email'],
            role=data.get('role', 'user'),
            department=data['department'],
            status='pending'  # User starts with pending status
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.flush()  # Get the user ID without committing
        
        # Create access request
        access_request = AccessRequest(
            user_id=user.id,
            department=data['department'],
            requested_role=data.get('role', 'user'),
            request_reason=data.get('request_reason', 'New user registration'),
            status='pending'
        )
        
        db.session.add(access_request)
        db.session.commit()
        
        # Log audit trail for user creation and access request
        _log_audit_trail(
            user_id=user.id,
            user_name=user.name,
            user_email=user.email,
            action='CREATE',
            table_name='users',
            record_id=user.id,
            new_values={
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'department': user.department,
                'status': 'pending'
            },
            additional_info='User registration - pending HR approval'
        )
        
        return jsonify({
            'message': 'User registration submitted successfully. Your account is pending HR approval.',
            'status': 'pending',
            'department': data['department']
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user and user.check_password(data['password']):
        # Check if user account is active
        if user.status == 'pending':
            return jsonify({
                'error': 'Account pending approval',
                'message': 'Your account is pending HR approval. Please contact your department HR.',
                'status': 'pending',
                'department': user.department
            }), 403
        elif user.status == 'rejected':
            return jsonify({
                'error': 'Account rejected',
                'message': 'Your account access has been rejected. Please contact your department HR for more information.',
                'status': 'rejected'
            }), 403
        elif user.status == 'active':
            # identity must be a string per spec in some environments
            access_token = create_access_token(identity=str(user.id))
            return jsonify({
                'access_token': access_token,
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'role': user.role,
                    'department': user.department,
                    'status': user.status
                }
            }), 200
        else:
            return jsonify({'error': 'Account status unknown'}), 500
    
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset - sends reset email to registered email"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        if not user:
            # Show clear message for unregistered email
            return jsonify({
                'error': 'Email not registered',
                'message': 'This email address is not registered in our system. Please enter a valid registered email address.',
                'email_exists': False
            }), 400
        
        # Generate reset token
        reset_token = _generate_reset_token()
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        # Create password reset record
        password_reset = PasswordReset(
            user_id=user.id,
            token=reset_token,
            expires_at=expires_at
        )
        
        # Remove any existing unused reset tokens for this user
        PasswordReset.query.filter_by(user_id=user.id, used=False).delete()
        
        db.session.add(password_reset)
        db.session.commit()
        
        # Send reset email
        email_sent = _send_password_reset_email(user.email, user.name, reset_token)
        
        # Generate reset link for console-based reset
        reset_link = f"http://localhost:3000/reset-password?token={reset_token}"
        
        # Log audit trail
        _log_audit_trail(
            user_id=user.id,
            user_name=user.name,
            user_email=user.email,
            action='PASSWORD_RESET_REQUEST',
            table_name='users',
            record_id=user.id,
            additional_info='Password reset requested'
        )
        
        return jsonify({
            'message': 'Password reset link generated successfully!',
            'email_sent': True,
            'email_exists': True,
            'reset_link': reset_link,
            'reset_token': reset_token
        }), 200
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Password reset request failed: {str(e)}'}), 500


@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    """Reset password using reset token"""
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')
        
        if not token or not new_password:
            return jsonify({'error': 'Token and new password are required'}), 400
        
        # Validate password strength
        is_valid, message = _validate_password(new_password)
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Find valid reset token
        password_reset = PasswordReset.query.filter_by(
            token=token,
            used=False
        ).first()
        
        if not password_reset:
            return jsonify({'error': 'Invalid or expired reset token'}), 400
        
        # Check if token has expired
        if datetime.utcnow() > password_reset.expires_at:
            return jsonify({'error': 'Reset token has expired'}), 400
        
        # Get user
        user = User.query.get(password_reset.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Update password
        user.set_password(new_password)
        
        # Mark token as used
        password_reset.used = True
        
        # Remove all other unused reset tokens for this user
        PasswordReset.query.filter_by(user_id=user.id, used=False).delete()
        
        db.session.commit()
        
        # Log audit trail
        _log_audit_trail(
            user_id=user.id,
            user_name=user.name,
            user_email=user.email,
            action='PASSWORD_RESET_COMPLETE',
            table_name='users',
            record_id=user.id,
            additional_info='Password reset completed successfully'
        )
        
        return jsonify({
            'message': 'Password reset successfully. You can now login with your new password.'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Password reset failed: {str(e)}'}), 500


@app.route('/api/auth/validate-reset-token', methods=['POST'])
def validate_reset_token():
    """Validate a password reset token"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'error': 'Token is required'}), 400
        
        # Find valid reset token
        password_reset = PasswordReset.query.filter_by(
            token=token,
            used=False
        ).first()
        
        if not password_reset:
            return jsonify({'valid': False, 'error': 'Invalid reset token'}), 400
        
        # Check if token has expired
        if datetime.utcnow() > password_reset.expires_at:
            return jsonify({'valid': False, 'error': 'Reset token has expired'}), 400
        
        return jsonify({
            'valid': True,
            'message': 'Token is valid'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Token validation failed: {str(e)}'}), 500


@app.route('/api/roles', methods=['GET'])
@jwt_required()
def get_roles():
    roles = Role.query.all()
    return jsonify([{
        'id': role.id,
        'title': role.title,
        'name': role.name,
        'department': role.department,
        'business_line': role.business_line,
        'criticality': role.criticality,
        'created_at': role.created_at.isoformat()
    } for role in roles])

@app.route('/api/roles', methods=['POST'])
@jwt_required()
def create_role():
    current_user_id = get_jwt_identity()
    # token identity stored as string; convert to int for lookup
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    
    if current_user.role not in ['admin', 'hr_manager']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        data = request.get_json()
        role = Role(**data)
        db.session.add(role)
        db.session.commit()
        
        # Log audit trail for role creation
        _log_audit_trail(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='CREATE',
            table_name='roles',
            record_id=role.id,
            new_values=data,
            additional_info='Role creation'
        )
        
        return jsonify({'message': 'Role created successfully', 'id': role.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/roles/<int:role_id>', methods=['PUT'])
@jwt_required()
def update_role(role_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    
    # Debug logging
    print(f"Role update attempt - User ID: {current_user_id}, User: {current_user}, Role: {current_user.role if current_user else 'None'}")
    
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    if not _has_hr_access(current_user.role):
        return jsonify({'error': 'Access denied. HR access required to manage roles.'}), 403
    
    try:
        role = Role.query.get_or_404(role_id)
        data = request.get_json()
        
        # Store old values for audit trail
        old_values = {
            'title': role.title,
            'name': role.name,
            'department': role.department,
            'business_line': role.business_line,
            'criticality': role.criticality
        }
        
        for key, value in data.items():
            if hasattr(role, key):
                setattr(role, key, value)
        
        db.session.commit()
        
        # Log audit trail for role update
        _log_audit_trail(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='UPDATE',
            table_name='roles',
            record_id=role.id,
            old_values=old_values,
            new_values=data,
            additional_info='Role update'
        )
        
        return jsonify({'message': 'Role updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/roles/<int:role_id>', methods=['DELETE'])
@jwt_required()
def delete_role(role_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    
    if not _has_hr_access(current_user.role):
        return jsonify({'error': 'Access denied. HR access required to manage roles.'}), 403
    
    try:
        role = Role.query.get_or_404(role_id)
        
        # Store role data for audit trail before deletion
        role_data = {
            'title': role.title,
            'name': role.name,
            'department': role.department,
            'business_line': role.business_line,
            'criticality': role.criticality
        }
        
        db.session.delete(role)
        db.session.commit()
        
        # Log audit trail for role deletion
        _log_audit_trail(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='DELETE',
            table_name='roles',
            record_id=role_id,
            old_values=role_data,
            additional_info='Role deletion'
        )
        
        return jsonify({'message': 'Role deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/succession-plans', methods=['GET'])
@jwt_required()
def get_succession_plans():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    
    # Check if user has HR access
    if not _has_hr_access(current_user.role):
        return jsonify({'error': 'Access denied. HR access required to view succession plans.'}), 403
    
    # Filter based on user permissions
    if current_user.role == 'admin':
        plans = SuccessionPlan.query.all()
    else:  # hr_manager
        plans = SuccessionPlan.query.join(Role).filter(Role.department == current_user.department).all()
    
    return jsonify([{
        'id': plan.id,
        'role_id': plan.role_id,
        'role_title': Role.query.get(plan.role_id).title if Role.query.get(plan.role_id) else 'Unknown Role',
        'incumbent_name': plan.incumbent_name,
        'incumbent_employee_id': plan.incumbent_employee_id,
        'incumbent_tenure': plan.incumbent_tenure,
        'retirement_date': plan.retirement_date.isoformat() if plan.retirement_date else None,
        'readiness_level': plan.readiness_level,
        'created_at': plan.created_at.isoformat(),
        'updated_at': plan.updated_at.isoformat()
    } for plan in plans])

@app.route('/api/succession-plans', methods=['POST'])
@jwt_required()
def create_succession_plan():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    
    if not _has_hr_access(current_user.role):
        return jsonify({'error': 'Access denied. HR access required to manage succession plans.'}), 403
    
    try:
        data = request.get_json() or {}
        # Validate required fields
        required = ['role_id', 'incumbent_name', 'incumbent_employee_id', 'incumbent_tenure', 'readiness_level']
        missing = [f for f in required if not str(data.get(f, '')).strip()]
        if missing:
            return jsonify({'error': f"Missing fields: {', '.join(missing)}"}), 400

        # Coerce and sanitize
        role_id = int(data['role_id'])
        incumbent_tenure = int(data['incumbent_tenure'])
        retirement_date = _parse_optional_date(data.get('retirement_date'))

        plan = SuccessionPlan(
            role_id=role_id,
            incumbent_name=data['incumbent_name'].strip(),
            incumbent_employee_id=data['incumbent_employee_id'].strip(),
            incumbent_tenure=incumbent_tenure,
            retirement_date=retirement_date,
            readiness_level=data['readiness_level']
        )
        db.session.add(plan)
        db.session.commit()
        
        # Log audit trail for succession plan creation
        _log_audit_trail(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='CREATE',
            table_name='succession_plans',
            record_id=plan.id,
            new_values=data,
            additional_info='Succession plan creation'
        )
        
        return jsonify({'message': 'Succession plan created successfully', 'id': plan.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/succession-plans/<int:plan_id>', methods=['PUT'])
@jwt_required()
def update_succession_plan(plan_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    
    if not _has_hr_access(current_user.role):
        return jsonify({'error': 'Access denied. HR access required to manage succession plans.'}), 403
    
    try:
        plan = SuccessionPlan.query.get_or_404(plan_id)
        data = request.get_json() or {}

        # Store old values for audit trail
        old_values = {
            'role_id': plan.role_id,
            'incumbent_name': plan.incumbent_name,
            'incumbent_employee_id': plan.incumbent_employee_id,
            'incumbent_tenure': plan.incumbent_tenure,
            'retirement_date': plan.retirement_date.isoformat() if plan.retirement_date else None,
            'readiness_level': plan.readiness_level
        }

        # Whitelist updates and coerce types
        if 'role_id' in data:
            plan.role_id = int(data['role_id'])
        if 'incumbent_name' in data:
            plan.incumbent_name = str(data['incumbent_name']).strip()
        if 'incumbent_employee_id' in data:
            plan.incumbent_employee_id = str(data['incumbent_employee_id']).strip()
        if 'incumbent_tenure' in data:
            plan.incumbent_tenure = int(data['incumbent_tenure'])
        if 'retirement_date' in data:
            plan.retirement_date = _parse_optional_date(data.get('retirement_date'))
        if 'readiness_level' in data:
            plan.readiness_level = data['readiness_level']
        
        db.session.commit()
        
        # Log audit trail for succession plan update
        _log_audit_trail(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='UPDATE',
            table_name='succession_plans',
            record_id=plan.id,
            old_values=old_values,
            new_values=data,
            additional_info='Succession plan update'
        )
        
        return jsonify({'message': 'Succession plan updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/succession-plans/<int:plan_id>', methods=['DELETE'])
@jwt_required()
def delete_succession_plan(plan_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id))
    
    if not _has_hr_access(current_user.role):
        return jsonify({'error': 'Access denied. HR access required to manage succession plans.'}), 403
    
    try:
        plan = SuccessionPlan.query.get_or_404(plan_id)
        
        # Store plan data for audit trail before deletion
        plan_data = {
            'role_id': plan.role_id,
            'incumbent_name': plan.incumbent_name,
            'incumbent_employee_id': plan.incumbent_employee_id,
            'incumbent_tenure': plan.incumbent_tenure,
            'retirement_date': plan.retirement_date.isoformat() if plan.retirement_date else None,
            'readiness_level': plan.readiness_level
        }
        
        db.session.delete(plan)
        db.session.commit()
        
        # Log audit trail for succession plan deletion
        _log_audit_trail(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='DELETE',
            table_name='succession_plans',
            record_id=plan_id,
            old_values=plan_data,
            additional_info='Succession plan deletion'
        )
        
        return jsonify({'message': 'Succession plan deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/analytics/demographics', methods=['GET'])
@jwt_required()
def get_demographics():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    try:
        # Department distribution
        dept_stats = db.session.query(
            Role.department,
            db.func.count(Role.id).label('count')
        ).group_by(Role.department).all()
        
        # Criticality distribution
        criticality_stats = db.session.query(
            Role.criticality,
            db.func.count(Role.id).label('count')
        ).group_by(Role.criticality).all()
        
        # Readiness level distribution
        readiness_stats = db.session.query(
            SuccessionPlan.readiness_level,
            db.func.count(SuccessionPlan.id).label('count')
        ).group_by(SuccessionPlan.readiness_level).all()
        
        return jsonify({
            'department_distribution': [{'department': d, 'count': c} for d, c in dept_stats],
            'criticality_distribution': [{'criticality': c, 'count': count} for c, count in criticality_stats],
            'readiness_distribution': [{'readiness': r, 'count': c} for r, c in readiness_stats]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/trends', methods=['GET'])
@jwt_required()
def get_trends():
    try:
        # Get historical data for the last 12 months
        end_date = datetime.now()
        start_date = end_date - timedelta(days=365)
        
        trends = db.session.query(
            db.func.date_trunc('month', HistoricalData.action_date).label('month'),
            db.func.count(HistoricalData.id).label('count')
        ).filter(
            HistoricalData.action_date >= start_date
        ).group_by(
            db.func.date_trunc('month', HistoricalData.action_date)
        ).order_by('month').all()
        
        return jsonify([{
            'month': trend.month.strftime('%Y-%m'),
            'count': trend.count
        } for trend in trends])
    except Exception as e:
        # If there's an error (like no historical data), return empty trends
        return jsonify([])

@app.route('/api/search', methods=['GET'])
@jwt_required()
def search():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    
    query = request.args.get('q', '')
    if not query:
        return jsonify([])
    
    # Search in roles
    roles = Role.query.filter(
        db.or_(
            Role.title.ilike(f'%{query}%'),
            Role.department.ilike(f'%{query}%'),
            Role.business_line.ilike(f'%{query}%')
        )
    ).limit(10).all()
    
    results = []
    for role in roles:
        results.append({
            'type': 'role',
            'id': role.id,
            'title': role.title,
            'department': role.department
        })
    
    # Only search in succession plans if user has HR access
    if _has_hr_access(current_user.role):
        plans = SuccessionPlan.query.filter(
            db.or_(
                SuccessionPlan.incumbent_name.ilike(f'%{query}%'),
                SuccessionPlan.incumbent_employee_id.ilike(f'%{query}%')
            )
        ).limit(10).all()
        
        for plan in plans:
            role = Role.query.get(plan.role_id)
            results.append({
                'type': 'succession_plan',
                'id': plan.id,
                'title': f"Succession Plan for {role.title if role else 'Unknown Role'}",
                'incumbent': plan.incumbent_name
            })
    
    return jsonify(results)

# ---------------------- Bulk upload from Excel ----------------------
@app.route('/api/upload/excel', methods=['POST'])
@jwt_required()
def upload_excel():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    if not current_user or not _has_hr_access(current_user.role):
        return jsonify({'error': 'Access denied. HR access required to upload data.'}), 403

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    try:
        # Read Excel
        xl = pd.ExcelFile(file)
        inserted = {'users': 0, 'roles': 0, 'plans': 0}

        # Sheet: Users (columns: name, email, role, department) - For Role Management Only
        if 'users' in [s.lower() for s in xl.sheet_names]:
            sheet_name = next(s for s in xl.sheet_names if s.lower() == 'users')
            df_users = xl.parse(sheet_name).fillna('')
            for _, u in df_users.iterrows():
                if not str(u.get('name', '')).strip():
                    continue
                
                # Create user entry for role management (not login account)
                user = User(
                    name=str(u.get('name', '')).strip(),
                    email=str(u.get('email', '')).strip() or f"{str(u.get('name', '')).strip().lower().replace(' ', '.')}@company.com",
                    role=str(u.get('role', '')).strip() or 'employee',
                    department=str(u.get('department', '')).strip() or current_user.department,
                    status='inactive'  # Not a login account, just for role management
                )
                
                # Set a dummy password (won't be used for login)
                user.set_password('NoLogin@123')
                
                db.session.add(user)
                inserted['users'] += 1
            
            db.session.commit()

        # Sheet: Roles (columns: title, name, department, business_line, criticality)
        if 'roles' in [s.lower() for s in xl.sheet_names]:
            sheet_name = next(s for s in xl.sheet_names if s.lower() == 'roles')
            df_roles = xl.parse(sheet_name).fillna('')
            for _, r in df_roles.iterrows():
                if not str(r.get('title', '')).strip():
                    continue
                role = Role(
                    title=str(r.get('title', '')).strip(),
                    name=str(r.get('name', '')).strip() or str(r.get('title', '')).strip(),
                    department=str(r.get('department', '')).strip() or current_user.department,
                    business_line=str(r.get('business_line', '')).strip() or 'Core Business',
                    criticality=str(r.get('criticality', '')).strip() or 'Medium'
                )
                db.session.add(role)
                inserted['roles'] += 1
            db.session.commit()

        # Build role title -> id map after role insertions
        title_to_id = {r.title: r.id for r in Role.query.all()}

        # Sheet: SuccessionPlans (columns: role_title or role_id, incumbent_name, incumbent_employee_id, incumbent_tenure, retirement_date, readiness_level)
        if 'successionplans' in [s.lower() for s in xl.sheet_names]:
            sheet_name = next(s for s in xl.sheet_names if s.lower() == 'successionplans')
            df_plans = xl.parse(sheet_name).fillna('')
            for _, p in df_plans.iterrows():
                role_id = None
                if str(p.get('role_id', '')).strip():
                    try:
                        role_id = int(p.get('role_id'))
                    except Exception:
                        role_id = None
                if role_id is None and str(p.get('role_title', '')).strip():
                    role_id = title_to_id.get(str(p.get('role_title')).strip())
                if not role_id:
                    continue

                plan = SuccessionPlan(
                    role_id=role_id,
                    incumbent_name=str(p.get('incumbent_name', '')).strip(),
                    incumbent_employee_id=str(p.get('incumbent_employee_id', '')).strip(),
                    incumbent_tenure=int(p.get('incumbent_tenure', 0) or 0),
                    retirement_date=_parse_optional_date(str(p.get('retirement_date', '')).strip()),
                    readiness_level=str(p.get('readiness_level', '')).strip() or '1-2 years'
                )
                db.session.add(plan)
                inserted['plans'] += 1
            db.session.commit()

        return jsonify({'message': 'Upload processed', 'inserted': inserted})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# ---------------------- Admin: Users management ----------------------
@app.route('/api/users', methods=['GET'])
@jwt_required()
def list_users():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    if not current_user or not _has_hr_access(current_user.role):
        return jsonify({'error': 'Insufficient permissions'}), 403

    # HR users can see users from their department, super admin (CCR) can see all
    if current_user.department == 'CCR':
        users = User.query.order_by(User.created_at.desc()).all()
    else:
        users = User.query.filter_by(department=current_user.department).order_by(User.created_at.desc()).all()
    
    return jsonify([{
        'id': u.id,
        'name': u.name,
        'email': u.email,
        'role': u.role,
        'department': u.department,
        'status': u.status,
        'created_at': u.created_at.isoformat(),
        'approved_at': u.approved_at.isoformat() if u.approved_at else None,
        'approved_by': u.approved_by
    } for u in users])

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    if not current_user or current_user.role != 'admin':
        return jsonify({'error': 'Insufficient permissions'}), 403

    if user_id == current_user.id:
        return jsonify({'error': 'Admins cannot delete themselves'}), 400

    user = User.query.get_or_404(user_id)
    try:
        # Store user data for audit trail before deletion
        user_data = {
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'department': user.department
        }
        
        # First, log audit trail for user deletion (before deleting the user)
        _log_audit_trail(
            user_id=current_user.id,
            user_name=current_user.name,
            user_email=current_user.email,
            action='DELETE',
            table_name='users',
            record_id=user_id,
            old_values=user_data,
            additional_info='User deletion by admin'
        )
        
        # Now delete the user
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': 'User deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# ---------------------- Audit Trail ----------------------
@app.route('/api/audit-trail', methods=['GET'])
@jwt_required()
def get_audit_trail():
    """Get audit trail - only accessible by HR users"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    
    if not current_user or not _has_hr_access(current_user.role):
        return jsonify({'error': 'Access denied. HR access required to view audit trail.'}), 403
    
    try:
        # Get query parameters for filtering
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)  # Max 100 per page
        action_filter = request.args.get('action', '')
        table_filter = request.args.get('table', '')
        user_filter = request.args.get('user', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        # Build query
        query = AuditLog.query
        
        if action_filter:
            query = query.filter(AuditLog.action == action_filter)
        if table_filter:
            query = query.filter(AuditLog.table_name == table_filter)
        if user_filter:
            query = query.filter(
                db.or_(
                    AuditLog.user_name.ilike(f'%{user_filter}%'),
                    AuditLog.user_email.ilike(f'%{user_filter}%')
                )
            )
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(AuditLog.timestamp >= from_date)
            except ValueError:
                pass
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(AuditLog.timestamp < to_date)
            except ValueError:
                pass
        
        # Order by timestamp (newest first)
        query = query.order_by(AuditLog.timestamp.desc())
        
        # Paginate results
        pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        audit_logs = []
        for log in pagination.items:
            audit_logs.append({
                'id': log.id,
                'user_id': log.user_id,
                'user_name': log.user_name,
                'user_email': log.user_email,
                'action': log.action,
                'table_name': log.table_name,
                'record_id': log.record_id,
                'old_values': json.loads(log.old_values) if log.old_values else None,
                'new_values': json.loads(log.new_values) if log.new_values else None,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'timestamp': log.timestamp.isoformat(),
                'additional_info': log.additional_info
            })
        
        return jsonify({
            'audit_logs': audit_logs,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/audit-trail/summary', methods=['GET'])
@jwt_required()
def get_audit_summary():
    """Get audit trail summary statistics - only accessible by HR users"""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(int(current_user_id)) if current_user_id is not None else None
    
    if not current_user or not _has_hr_access(current_user.role):
        return jsonify({'error': 'Access denied. HR access required to view audit summary.'}), 403
    
    try:
        # Get summary statistics
        total_actions = AuditLog.query.count()
        
        # Actions by type
        actions_by_type = db.session.query(
            AuditLog.action,
            db.func.count(AuditLog.id).label('count')
        ).group_by(AuditLog.action).all()
        
        # Actions by table
        actions_by_table = db.session.query(
            AuditLog.table_name,
            db.func.count(AuditLog.id).label('count')
        ).group_by(AuditLog.table_name).all()
        
        # Actions by user
        actions_by_user = db.session.query(
            AuditLog.user_name,
            db.func.count(AuditLog.id).label('count')
        ).group_by(AuditLog.user_name).order_by(db.func.count(AuditLog.id).desc()).limit(10).all()
        
        # Recent activity (last 7 days)
        week_ago = datetime.now() - timedelta(days=7)
        recent_activity = db.session.query(
            db.func.date(AuditLog.timestamp).label('date'),
            db.func.count(AuditLog.id).label('count')
        ).filter(AuditLog.timestamp >= week_ago).group_by(
            db.func.date(AuditLog.timestamp)
        ).order_by(db.func.date(AuditLog.timestamp)).all()
        
        return jsonify({
            'total_actions': total_actions,
            'actions_by_type': [{'action': a, 'count': c} for a, c in actions_by_type],
            'actions_by_table': [{'table': t, 'count': c} for t, c in actions_by_table],
            'actions_by_user': [{'user': u, 'count': c} for u, c in actions_by_user],
            'recent_activity': [{'date': d.isoformat(), 'count': c} for d, c in recent_activity]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Access Request Management Endpoints
@app.route('/api/access-requests', methods=['GET'])
@jwt_required()
def get_access_requests():
    """Get access requests - HR users can see all, regular users see only their own"""
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(int(current_user_id))
        
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        if _has_hr_access(current_user.role):
            # HR users can see access requests based on their department
            if current_user.role == 'admin':
                # Admin users can see requests from their own department
                access_requests = AccessRequest.query.filter_by(department=current_user.department).all()
            else:
                # Other HR users can only see requests from their department
                access_requests = AccessRequest.query.filter_by(department=current_user.department).all()
        else:
            # Regular users can only see their own requests
            access_requests = AccessRequest.query.filter_by(user_id=current_user.id).all()
        
        requests_data = []
        for req in access_requests:
            user = User.query.get(req.user_id)
            hr_approver = User.query.get(req.hr_approver_id) if req.hr_approver_id else None
            
            requests_data.append({
                'id': req.id,
                'user_id': req.user_id,
                'user_name': user.name if user else 'Unknown User',
                'user_email': user.email if user else 'Unknown Email',
                'department': req.department,
                'requested_role': req.requested_role,
                'request_reason': req.request_reason,
                'status': req.status,
                'hr_approver_id': req.hr_approver_id,
                'hr_approver_name': hr_approver.name if hr_approver else None,
                'approved_at': req.approved_at.isoformat() if req.approved_at else None,
                'rejected_at': req.rejected_at.isoformat() if req.rejected_at else None,
                'rejection_reason': req.rejection_reason,
                'created_at': req.created_at.isoformat(),
                'updated_at': req.updated_at.isoformat()
            })
        
        return jsonify(requests_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/access-requests/<int:request_id>/approve', methods=['POST'])
@jwt_required()
def approve_access_request(request_id):
    """Approve an access request - Only HR users can approve"""
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(int(current_user_id))
        
        if not current_user or not _has_hr_access(current_user.role):
            return jsonify({'error': 'Access denied. HR access required to approve requests.'}), 403
        
        # Check if user can approve this request (same department or super admin)
        access_request = AccessRequest.query.get(request_id)
        if not access_request:
            return jsonify({'error': 'Access request not found'}), 404
        
        # Check if user can approve this request (same department)
        if current_user.department != access_request.department:
            return jsonify({'error': 'Access denied. You can only approve requests from your department.'}), 403
        
        # Update access request status
        access_request.status = 'approved'
        access_request.hr_approver_id = current_user.id
        access_request.approved_at = datetime.utcnow()
        
        # Update user status
        user = User.query.get(access_request.user_id)
        if user:
            user.status = 'active'
            user.approved_at = datetime.utcnow()
            user.approved_by = current_user.id
            
            # Log the approval
            _log_audit_trail(
                user_id=current_user.id,
                user_name=current_user.name,
                user_email=current_user.email,
                action='APPROVE_ACCESS_REQUEST',
                table_name='access_requests',
                record_id=request_id,
                new_values={'status': 'approved', 'hr_approver_id': current_user.id},
                additional_info=f'Approved access request for user {user.email}'
            )
        
        db.session.commit()
        
        return jsonify({
            'message': 'Access request approved successfully',
            'request_id': request_id,
            'user_email': user.email if user else 'Unknown'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/access-requests/<int:request_id>/reject', methods=['POST'])
@jwt_required()
def reject_access_request(request_id):
    """Reject an access request - Only HR users can reject"""
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(int(current_user_id))
        
        if not current_user or not _has_hr_access(current_user.role):
            return jsonify({'error': 'Access denied. HR access required to reject requests.'}), 403
        
        # Check if user can reject this request (same department or super admin)
        access_request = AccessRequest.query.get(request_id)
        if not access_request:
            return jsonify({'error': 'Access request not found'}), 404
        
        # Check if user can reject this request (same department)
        if current_user.department != access_request.department:
            return jsonify({'error': 'Access denied. You can only reject requests from your department.'}), 403
        
        data = request.get_json()
        rejection_reason = data.get('rejection_reason', 'No reason provided')
        
        # Update access request status
        access_request.status = 'rejected'
        access_request.hr_approver_id = current_user.id
        access_request.rejected_at = datetime.utcnow()
        access_request.rejection_reason = rejection_reason
        
        # Update user status
        user = User.query.get(access_request.user_id)
        if user:
            user.status = 'rejected'
            
            # Log the rejection
            _log_audit_trail(
                user_id=current_user.id,
                user_name=current_user.name,
                user_email=current_user.email,
                action='REJECT_ACCESS_REQUEST',
                table_name='access_requests',
                record_id=request_id,
                new_values={'status': 'rejected', 'rejection_reason': rejection_reason},
                additional_info=f'Rejected access request for user {user.email}'
            )
        
        db.session.commit()
        
        return jsonify({
            'message': 'Access request rejected successfully',
            'request_id': request_id,
            'user_email': user.email if user else 'Unknown'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/access-requests/stats', methods=['GET'])
@jwt_required()
def get_access_request_stats():
    """Get access request statistics - Only HR users can access"""
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(int(current_user_id))
        
        if not current_user or not _has_hr_access(current_user.role):
            return jsonify({'error': 'Access denied. HR access required to view statistics.'}), 403
        
        # Get statistics based on user's department access
        if current_user.role == 'admin':
            # Admin users can see statistics from their own department
            total_requests = AccessRequest.query.filter_by(department=current_user.department).count()
            pending_requests = AccessRequest.query.filter_by(department=current_user.department, status='pending').count()
            approved_requests = AccessRequest.query.filter_by(department=current_user.department, status='approved').count()
            rejected_requests = AccessRequest.query.filter_by(department=current_user.department, status='rejected').count()
            
            dept_stats = [{
                'department': current_user.department,
                'total': total_requests,
                'pending': pending_requests,
                'approved': approved_requests,
                'rejected': rejected_requests
            }]
        else:
            # Other HR users can only see their department stats
            total_requests = AccessRequest.query.filter_by(department=current_user.department).count()
            pending_requests = AccessRequest.query.filter_by(department=current_user.department, status='pending').count()
            approved_requests = AccessRequest.query.filter_by(department=current_user.department, status='approved').count()
            rejected_requests = AccessRequest.query.filter_by(department=current_user.department, status='rejected').count()
            
            dept_stats = [{
                'department': current_user.department,
                'total': total_requests,
                'pending': pending_requests,
                'approved': approved_requests,
                'rejected': rejected_requests
            }]
        
        return jsonify({
            'total_requests': total_requests,
            'pending_requests': pending_requests,
            'approved_requests': approved_requests,
            'rejected_requests': rejected_requests,
            'department_stats': dept_stats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if none exists
        if not User.query.filter_by(role='admin').first():
            admin = User(
                name='Admin User',
                email='admin@company.com',
                role='admin',
                department='HR'
            )
            admin.set_password('Admin123!')
            db.session.add(admin)
            db.session.commit()
            
        # Create some sample roles if none exist
        if not Role.query.first():
            sample_roles = [
                            Role(title='HR Director', name='HR Director', department='HR', business_line='Core Business', criticality='High'),
            Role(title='Finance Manager', name='Finance Manager', department='Finance', business_line='Core Business', criticality='High'),
            Role(title='Operations Lead', name='Operations Lead', department='Operations', business_line='Core Business', criticality='Medium'),
            Role(title='Technology Manager', name='Technology Manager', department='Technology', business_line='Core Business', criticality='High'),
            Role(title='Sales Director', name='Sales Director', department='Sales', business_line='Core Business', criticality='Medium'),
            ]
            for role in sample_roles:
                db.session.add(role)
            db.session.commit()
            
        # Create some sample succession plans if none exist
        if not SuccessionPlan.query.first():
            sample_plans = [
                SuccessionPlan(
                    role_id=1,  # HR Director
                    incumbent_name='John Smith',
                    incumbent_employee_id='EMP001',
                    incumbent_tenure=36,
                    readiness_level='Ready Now'
                ),
                SuccessionPlan(
                    role_id=2,  # Finance Manager
                    incumbent_name='Sarah Johnson',
                    incumbent_employee_id='EMP002',
                    incumbent_tenure=24,
                    readiness_level='1-2 years'
                ),
            ]
            for plan in sample_plans:
                db.session.add(plan)
            db.session.commit()
    
    app.run(debug=True, host='0.0.0.0', port=5001)
