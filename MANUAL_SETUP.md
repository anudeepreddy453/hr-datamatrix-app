# 🚀 HR DataMatrix - Manual Setup Guide

## 📋 **Prerequisites**
- **Python 3.9+** installed on your system
- **Node.js 16+** installed on your system
- **npm** (comes with Node.js)
- **Git** (to clone the repository)

## 🔧 **Step-by-Step Setup**

### **Step 1: Clone and Navigate**
```bash
git clone <your-repo-url>
cd hr-datamatrix-main
```

### **Step 2: Backend Setup (Flask)**

#### **2.1 Create Virtual Environment**
```bash
cd backend
python3 -m venv venv
```

#### **2.2 Activate Virtual Environment**
**On macOS/Linux:**
```bash
source venv/bin/activate
```

**On Windows:**
```bash
venv\Scripts\activate
```

#### **2.3 Install Python Dependencies**
```bash
pip install -r requirements.txt
```

#### **2.4 Set up Environment Variables**
```bash
cp env.example .env
```
**Edit `.env` file** with your configuration (optional for development)

#### **2.5 Start Flask Backend**
```bash
python3 app.py
```

**✅ Backend is now running on**: http://localhost:5001

**Keep this terminal open!** The backend needs to keep running.

---

### **Step 3: Frontend Setup (React)**

#### **3.1 Open a NEW Terminal Window/Tab**
Navigate to the project root:
```bash
cd /path/to/hr-datamatrix-main
```

#### **3.2 Navigate to Frontend Directory**
```bash
cd frontend
```

#### **3.3 Install Node.js Dependencies**
```bash
npm install
```
This will download all required packages from npm registry.

#### **3.4 Start React Development Server**
```bash
npm start
```

**✅ Frontend is now running on**: http://localhost:3000

**Keep this terminal open too!** The frontend needs to keep running.

---

## 🌐 **Access Your Application**

- **Frontend (Main App)**: http://localhost:3000
- **Backend API**: http://localhost:5001

## 🔐 **Login Credentials**

Use any of these pre-configured HR admin accounts:

| Email | Password | Role | Department |
|-------|----------|------|------------|
| priya.sharma@ccr.com | Priya@123 | admin | CCR |
| rohan.mehta@i2r.com | Rohan@123 | admin | I2R |
| anjali.verma@mkd.com | Anjali@123 | admin | MKD |
| vikram.rao@bacardi.com | Vikram@123 | admin | Bacardi |
| sneha.kapoor@xone.com | Sneha@123 | admin | Xone |
| arjun.malhotra@cis.com | Arjun@123 | admin | CIS |
| neha.singh@dir.com | Neha@123 | admin | DIR |
| karan.patel@cqis.com | Karan@123 | admin | CQIS |
| meera.nair@osd.com | Meera@123 | admin | OSD |
| suresh.reddy@dat.com | Suresh@123 | admin | DAT |
| aditi.joshi@dlf.com | Aditi@123 | admin | DLF |
| kavya.menon@riskweb.com | Kavya@123 | admin | Riskweb |

## 🛑 **Stopping the Application**

- **Backend**: Press `Ctrl+C` in the backend terminal
- **Frontend**: Press `Ctrl+C` in the frontend terminal

## 🔄 **Restarting**

To restart either service:
1. Stop it with `Ctrl+C`
2. Run the start command again:
   - **Backend**: `python3 app.py` (with venv activated)
   - **Frontend**: `npm start`

## 🆘 **Troubleshooting**

### **Port Already in Use**
If you get "port already in use" errors:
- Check if another instance is running
- Kill the process using the port
- Or use different ports by editing configuration

### **Dependencies Not Found**
- Make sure virtual environment is activated for backend
- Make sure you're in the correct directory
- Try deleting `node_modules` and running `npm install` again

### **Database Issues**
- The SQLite database will be created automatically on first run
- Check that the `backend` directory is writable

## 📁 **Directory Structure**
```
hr-datamatrix-main/
├── backend/                 # Flask backend
│   ├── app.py              # Main Flask application
│   ├── requirements.txt    # Python dependencies
│   ├── env.example        # Environment template
│   └── venv/              # Virtual environment (created)
├── frontend/               # React frontend
│   ├── src/                # React source code
│   ├── package.json        # Node.js dependencies
│   └── node_modules/       # Installed packages (created)
└── README.md               # Main documentation
```

---

**🎉 You're all set! Your HR DataMatrix application is now running manually!**
