# 🚀 HR DataMatrix - Windows Office Laptop Setup Guide

## 📋 **Prerequisites (Must Install on Office Laptop)**

### **1. Python 3.11.0**
- **Download**: https://python.org/downloads/
- **Version**: Python 3.11.0 (exact version)
- **Important**: ✅ Check "Add Python to PATH" during installation
- **Verify**: Open Command Prompt and run `python --version`

### **2. Node.js 16+**
- **Download**: https://nodejs.org/
- **Version**: LTS version (16.x or higher)
- **Important**: ✅ Check "Add to PATH" during installation
- **Verify**: Open Command Prompt and run `node --version`

## 🎯 **Quick Start (One-Click Setup)**

### **Method 1: Double-Click Setup (Recommended)**
1. **Extract** the ZIP file to a folder (e.g., `C:\Projects\hr-datamatrix`)
2. **Double-click** `start_windows.bat`
3. **Wait** for everything to install and start
4. **Access** your application at http://localhost:3000

### **Method 2: Command Prompt**
```cmd
# Navigate to project folder
cd C:\path\to\hr-datamatrix

# Run setup script
start_windows.bat
```

## 🔧 **What the Setup Script Does Automatically**

1. ✅ **Checks** Python 3.11 and Node.js installation
2. ✅ **Creates** Python virtual environment
3. ✅ **Installs** all Python packages from `portable_packages` folder
4. ✅ **Installs** all Node.js dependencies
5. ✅ **Starts** Flask backend on port 5001
6. ✅ **Starts** React frontend on port 3000
7. ✅ **Opens** separate windows for each service

## 📁 **Project Structure for Windows**

```
hr-datamatrix/
├── backend/                    # Flask backend
│   ├── app.py                 # Main application
│   ├── requirements.txt       # Python dependencies list
│   ├── venv/                  # Virtual environment (created by script)
│   └── instance/              # Database files
├── frontend/                   # React frontend
│   ├── src/                   # React source code
│   ├── package.json           # Node.js dependencies
│   └── node_modules/          # Installed packages (created by script)
├── portable_packages/          # Pre-downloaded Python packages
│   ├── flask-2.3.3-py3-none-any.whl
│   ├── flask-sqlalchemy-3.0.5-py3-none-any.whl
│   ├── flask-cors-4.0.0-py2.py3-none-any.whl
│   └── ... (all other packages)
├── start_windows.bat           # Windows setup script
├── start.sh                    # macOS/Linux script (not needed on Windows)
├── README.md                   # Main documentation
└── WINDOWS_SETUP_README.md     # This file
```

## 🚨 **Troubleshooting Common Issues**

### **Error 1: "python" is not recognized**
- **Solution**: Install Python 3.11 from python.org
- **Important**: Check "Add Python to PATH" during installation
- **Verify**: Restart Command Prompt after installation

### **Error 2: "node" is not recognized**
- **Solution**: Install Node.js from nodejs.org
- **Important**: Check "Add to PATH" during installation
- **Verify**: Restart Command Prompt after installation

### **Error 3: Port already in use**
- **Solution**: Close other applications using ports 3000 or 5001
- **Or**: Restart your computer
- **Check**: Use `netstat -an | findstr :3000` to see what's using the port

### **Error 4: Permission denied**
- **Solution**: Run Command Prompt as Administrator
- **Or**: Right-click `start_windows.bat` → "Run as administrator"

### **Error 5: Virtual environment creation failed**
- **Solution**: Make sure Python 3.11 is properly installed
- **Check**: Run `python --version` in Command Prompt
- **Alternative**: Delete `backend\venv` folder and try again

## 🔐 **Default Login Accounts**

After successful setup, use these accounts to login:

| Email | Password | Role |
|-------|----------|------|
| `kavya.menon@riskweb.com` | `Kavya@123` | HR Operations Specialist |
| `priya.sharma@ccr.com` | `Priya@123` | HR Manager |
| `amit.patel@ccr.com` | `Amit@123` | HR Business Partner |

## 🌐 **Access Your Application**

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5001

## 🛠️ **Manual Setup (If Script Fails)**

### **Backend Setup**
```cmd
cd backend
python -m venv venv
venv\Scripts\activate
cd ..\portable_packages
pip install --no-index --find-links . flask==2.3.3 flask-sqlalchemy==3.0.5 flask-cors==4.0.0 flask-jwt-extended==4.5.3 flask-bcrypt==1.0.1 python-dotenv==1.0.0 werkzeug==2.3.7 sqlalchemy==2.0.21 psycopg2-binary==2.9.7 pandas==2.0.3 numpy==1.24.3 openpyxl==3.1.2
cd ..\backend
python app.py
```

### **Frontend Setup**
```cmd
cd frontend
npm install
npm start
```

## 💡 **Pro Tips for Office Use**

1. **Run as Administrator** if you get permission errors
2. **Close other applications** that might use the same ports
3. **Keep the terminal windows open** - closing them stops the services
4. **Bookmark the URLs** for easy access
5. **Use the pre-configured accounts** - no need to create new ones initially

## 🔄 **Updating the Application**

1. **Download** the latest ZIP from GitHub
2. **Extract** to a new folder
3. **Run** `start_windows.bat` again
4. **All packages** will be automatically updated

## 📞 **Need Help?**

- **Check**: This README file first
- **GitHub**: Create an issue in the repository
- **Documentation**: Read the main README.md file

---

**🚀 Your HR DataMatrix is now ready for Windows office use!**
