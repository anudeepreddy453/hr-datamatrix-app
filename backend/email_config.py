#!/usr/bin/env python3
"""
Simple email configuration for password reset
You can modify these settings to use your own email
"""

# Email Configuration
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'smtp_username': 'your-email@gmail.com',  # Replace with your Gmail
    'smtp_password': 'your-app-password',     # Replace with your Gmail App Password
    'from_name': 'HR Succession Planning System'
}

# Instructions for Gmail setup:
# 1. Go to your Google Account settings
# 2. Enable 2-Factor Authentication
# 3. Generate an App Password for this application
# 4. Replace the smtp_username and smtp_password above
# 5. Save this file and restart the backend server

def get_email_config():
    """Get email configuration"""
    return EMAIL_CONFIG

def is_email_configured():
    """Check if email is properly configured"""
    config = get_email_config()
    return (config['smtp_username'] != 'your-email@gmail.com' and 
            config['smtp_password'] != 'your-app-password')
