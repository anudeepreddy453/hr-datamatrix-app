# 🚀 HR DataMatrix - HR Data Management & Scalability Platform

A comprehensive web application for managing HR data, succession planning, role management, user access control, and audit trails. Built with Flask backend and React frontend, designed for scalability and efficient HR data management.

## ✨ Features

### 🔐 **Authentication & Authorization**
- **Role-Based Access Control (RBAC)**: Admin, HR Manager, and User roles
- **Secure Login/Logout**: JWT-based authentication
- **Password Reset**: Console-based password reset system
- **User Registration**: HR-approved account creation workflow

### 👥 **User Management**
- **HR Personnel Management**: 11 pre-configured HR admin users
- **Department-Based Access**: Users can only access their department's data
- **Access Request System**: New user accounts require HR approval
- **User Status Management**: Active, pending, and rejected user states

### 🎯 **Role Management**
- **Comprehensive Role System**: HR, IT, Finance, Operations, and more
- **Department Mapping**: Roles linked to specific departments
- **Excel Import/Export**: Bulk role management capabilities
- **Audit Trail**: Complete history of role changes

### 📊 **Succession Planning**
- **HR-Only Access**: Succession plans visible only to HR personnel
- **Incumbent Tracking**: Track current role holders
- **Successor Planning**: Plan future role transitions
- **Department Filtering**: View plans by department

### 📈 **Analytics Dashboard**
- **Real-time Metrics**: User counts, role distributions
- **Department Analytics**: Performance by department
- **Visual Charts**: Interactive data visualization
- **Time-based Reporting**: Historical data analysis

### 🔍 **Audit & Compliance**
- **Complete Audit Trail**: Track all system changes
- **Change History**: Who changed what and when
- **HR Audit Panel**: Dedicated interface for compliance
- **Timestamp Logging**: Indian Standard Time (IST) tracking

### 🎨 **Modern UI/UX**
- **Responsive Design**: Works on all devices
- **Tailwind CSS**: Modern, professional styling
- **Interactive Components**: Smooth animations and transitions
- **Professional Interface**: Clean, intuitive user experience

## 🏗️ Architecture

### **Backend (Flask)**
- **Framework**: Flask 2.3.3
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: JWT with Flask-JWT-Extended
- **Security**: Bcrypt password hashing
- **CORS**: Cross-origin resource sharing enabled

### **Frontend (React)**
- **Framework**: React 18
- **Styling**: Tailwind CSS
- **HTTP Client**: Axios
- **Routing**: React Router DOM
- **Icons**: Lucide React

## 🚀 Manual Setup & Startup

### **Prerequisites**
- Python 3.9+
- Node.js 16+
- npm or yarn

### **1. Clone the Repository**
```bash
git clone <your-repo-url>
cd hr-datamatrix-main
```

### **2. Backend Setup (Flask)**

#### **Create Python Virtual Environment**
```bash
cd backend
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

#### **Install Python Dependencies**
```bash
pip install -r requirements.txt
```

#### **Set up Environment Variables**
```bash
cp env.example .env
# Edit .env with your configuration
```

#### **Start Flask Backend**
```bash
python3 app.py
```
**Backend will run on**: http://localhost:5001

### **3. Frontend Setup (React)**

#### **Open New Terminal & Navigate to Frontend**
```bash
cd frontend
```

#### **Install Node.js Dependencies**
```bash
npm install
```

#### **Start React Development Server**
```bash
npm start
```
**Frontend will run on**: http://localhost:3000

### **4. Access Your Application**

- **Frontend (Main App)**: http://localhost:3000
- **Backend API**: http://localhost:5001

### **5. Default Login Credentials**

| Email | Password | Role |
|-------|----------|------|
| kavya.menon@riskweb.com | Kavya@123 | HR Operations Specialist |
| priya.sharma@ccr.com | Priya@123 | HR Manager |
| amit.patel@ccr.com | Amit@123 | HR Business Partner |

## 🔧 Configuration

### **Environment Variables**
Create a `.env` file in the backend directory:

```env
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here
DATABASE_URL=sqlite:///hr_succession.db
```

### **Database Setup**
The application will automatically create the database on first run. For production, consider using PostgreSQL or MySQL.

## 👥 Default Users

### **HR Admin Users (Pre-configured)**
| Department | Name | Email | Role | Password |
|------------|------|-------|------|----------|
| CCR | Priya Sharma | priya.sharma@ccr.com | admin | Priya@123 |
| I2R | Rohan Mehta | rohan.mehta@i2r.com | admin | Rohan@123 |
| MKD | Anjali Verma | anjali.verma@mkd.com | admin | Anjali@123 |
| Bacardi | Vikram Rao | vikram.rao@bacardi.com | admin | Vikram@123 |
| Xone | Sneha Kapoor | sneha.kapoor@xone.com | admin | Sneha@123 |
| CIS | Arjun Malhotra | arjun.malhotra@cis.com | admin | Arjun@123 |
| DIR | Neha Singh | neha.singh@dir.com | admin | Neha@123 |
| CQIS | Karan Patel | karan.patel@cqis.com | admin | Karan@123 |
| OSD | Meera Nair | meera.nair@osd.com | admin | Meera@123 |
| DAT | Suresh Reddy | suresh.reddy@dat.com | admin | Suresh@123 |
| DLF | Aditi Joshi | aditi.joshi@dlf.com | admin | Aditi@123 |
| Riskweb | Kavya Menon | kavya.menon@riskweb.com | admin | Kavya@123 |

## 📁 Project Structure

```
hr-datamatrix-main/
├── backend/                 # Flask backend
│   ├── app.py              # Main application file
│   ├── requirements.txt    # Python dependencies
│   ├── env.example        # Environment variables template
│   ├── instance/          # Database files
│   └── venv/              # Virtual environment (auto-created)
├── frontend/               # React frontend
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── contexts/      # React contexts
│   │   └── App.js         # Main app component
│   ├── package.json       # Node.js dependencies
│   └── tailwind.config.js # Tailwind CSS configuration
├── requirements.txt        # Python dependencies (installed from PyPI)
├── package.json           # Node.js dependencies (installed from npm)
├── .gitignore             # Git ignore file
└── README.md              # This file
```

## 🔒 Security Features

- **JWT Authentication**: Secure token-based authentication
- **Password Hashing**: Bcrypt encryption for passwords
- **Role-Based Access**: Granular permission system
- **CORS Protection**: Cross-origin request security
- **Input Validation**: Server-side data validation
- **Audit Logging**: Complete change tracking

## 📊 API Endpoints

### **Authentication**
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/forgot-password` - Password reset request
- `POST /api/auth/reset-password` - Password reset
- `POST /api/auth/validate-reset-token` - Token validation

### **Users**
- `GET /api/users` - Get all users (HR only)
- `PUT /api/users/<id>` - Update user
- `DELETE /api/users/<id>` - Delete user
- `GET /api/users/me` - Get current user

### **Roles**
- `GET /api/roles` - Get all roles
- `POST /api/roles` - Create new role
- `PUT /api/roles/<id>` - Update role
- `DELETE /api/roles/<id>` - Delete role
- `POST /api/roles/import` - Import roles from Excel
- `GET /api/roles/export` - Export roles to Excel

### **Succession Plans**
- `GET /api/succession-plans` - Get succession plans (HR only)
- `POST /api/succession-plans` - Create succession plan
- `PUT /api/succession-plans/<id>` - Update succession plan
- `DELETE /api/succession-plans/<id>` - Delete succession plan

### **Access Requests**
- `GET /api/access-requests` - Get access requests (HR only)
- `PUT /api/access-requests/<id>` - Approve/reject request

### **Audit Logs**
- `GET /api/audit-logs` - Get audit logs (HR only)

## 🚀 Deployment

### **Development**
```bash
# Backend (Terminal 1)
cd backend
source venv/bin/activate  # On macOS/Linux
python3 app.py

# Frontend (Terminal 2)
cd frontend
npm start
```

### **Production**
1. **Backend**: Deploy to cloud platform (Heroku, AWS, etc.)
2. **Frontend**: Build and deploy to CDN
3. **Database**: Use production database (PostgreSQL, MySQL)
4. **Environment**: Set production environment variables

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is open source and available under the [MIT License](LICENSE).

## 🆘 Support

For support and questions:
- Create an issue in the GitHub repository
- Contact the development team
- Check the documentation

## 🔄 Updates & Maintenance

- **Regular Updates**: Security patches and bug fixes
- **Feature Additions**: New functionality based on user feedback
- **Performance Optimization**: Continuous improvement
- **Security Audits**: Regular security reviews

---

**Built with ❤️ for modern HR data management and scalability**
