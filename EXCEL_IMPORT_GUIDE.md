# 📊 Excel Import Guide - HR DataMatrix

## 🚀 **Overview**

The Excel import feature allows you to bulk upload users, roles, and succession plans from Excel files. This is perfect for initial data setup or bulk updates.

## 📁 **Supported Excel Sheets**

### **1. Users Sheet**
**Purpose**: Import multiple users for role management and succession planning (NOT for login accounts)
**Columns**:
- `name` (Required): Full name of the user
- `email` (Optional): Email address (auto-generated if not provided)
- `role` (Optional): User role (defaults to 'employee')
- `department` (Optional): Department (defaults to uploader's department)

**Example**:
| name | email | role | department |
|------|-------|------|------------|
| John Doe | john.doe@company.com | HR Manager | CCR |
| Jane Smith | | employee | I2R |
| Bob Wilson | bob.wilson@company.com | admin | MKD |

### **2. Roles Sheet**
**Purpose**: Import multiple roles for succession planning
**Columns**:
- `title` (Required): Role title
- `name` (Optional): Role name (defaults to title)
- `department` (Optional): Department (defaults to uploader's department)
- `business_line` (Optional): Business line (defaults to 'Core Business')
- `criticality` (Optional): Criticality level (defaults to 'Medium')

**Example**:
| title | name | department | business_line | criticality |
|-------|------|------------|---------------|-------------|
| HR Director | HR Director | CCR | Core Business | High |
| Finance Manager | Finance Manager | Finance | Core Business | High |
| Operations Lead | Operations Lead | Operations | Core Business | Medium |

### **3. SuccessionPlans Sheet**
**Purpose**: Import succession plans for roles
**Columns**:
- `role_title` or `role_id` (Required): Role title or ID
- `incumbent_name` (Required): Current employee name
- `incumbent_employee_id` (Required): Employee ID
- `incumbent_tenure` (Optional): Years of service (defaults to 0)
- `retirement_date` (Optional): Expected retirement date (YYYY-MM-DD)
- `readiness_level` (Optional): Succession readiness (defaults to '1-2 years')

**Example**:
| role_title | incumbent_name | incumbent_employee_id | incumbent_tenure | retirement_date | readiness_level |
|------------|----------------|----------------------|------------------|-----------------|-----------------|
| HR Director | John Smith | EMP001 | 8 | 2026-12-31 | Ready Now |
| Finance Manager | Sarah Johnson | EMP002 | 5 | 2027-06-30 | 1-2 years |

## 🔧 **How to Use**

### **Step 1: Prepare Your Excel File**
1. Create an Excel file (.xlsx or .xls)
2. Add the required sheets: `users`, `roles`, `successionplans`
3. Fill in the data according to the column specifications above
4. Save the file

### **Step 2: Upload via Frontend**
1. Navigate to **Users (Admin)** page
2. Click **"Import Excel"** button
3. Select your Excel file
4. Wait for the upload confirmation

### **Step 3: Verify Import**
1. Check the success message showing counts
2. Navigate to respective sections to verify data
3. Users will appear in **Users Admin**
4. Roles will appear in **Role Management**
5. Succession Plans will appear in **Succession Plans**

## ⚠️ **Important Notes**

### **Users Import**:
- ✅ **Role Management Only**: Imported users are for succession planning, NOT login accounts
- ✅ **Status**: Users have `status='inactive'` (cannot login)
- ✅ **Auto-generated emails**: If no email provided, generates company email format
- ✅ **Department assignment**: If no department specified, uses uploader's department
- ✅ **No login access**: These users cannot access the system

### **Roles Import**:
- ✅ **Auto-created**: Roles are immediately available
- ✅ **Department assignment**: If no department specified, uses uploader's department
- ✅ **Default values**: Business line and criticality have sensible defaults

### **Succession Plans Import**:
- ✅ **Role linking**: Automatically links to existing roles
- ✅ **Flexible input**: Accepts either role_title or role_id
- ✅ **Default values**: Tenure and readiness have sensible defaults

## 🎯 **Best Practices**

1. **Test with small files first** to verify format
2. **Use consistent department names** across sheets
3. **Provide passwords** for users when possible
4. **Verify role titles** match between roles and succession plans sheets
5. **Backup existing data** before large imports

## 🚨 **Error Handling**

- **Missing required columns**: Row will be skipped
- **Invalid data**: Row will be skipped, others will continue
- **Duplicate emails**: Existing users are skipped
- **Database errors**: Transaction is rolled back, no data is inserted

## 📋 **Sample Excel File Structure**

```
Excel File: hr_import.xlsx
├── Sheet: users
│   ├── name | email | role | department
│   └── John Doe | john@company.com | HR Manager | CCR
├── Sheet: roles
│   ├── title | name | department | business_line | criticality
│   └── HR Director | HR Director | CCR | Core Business | High
└── Sheet: successionplans
    ├── role_title | incumbent_name | employee_id | tenure | retirement | readiness
    └── HR Director | John Smith | EMP001 | 8 | 2026-12-31 | Ready Now
```

## 🎉 **Benefits**

- **Bulk data import** saves time
- **Consistent data structure** ensures quality
- **Automatic validation** prevents errors
- **Role management setup** for succession planning
- **No manual entry** required
- **Clear separation** between login users and role management users

---

**💡 Tip**: Start with a small test file to verify your Excel format before importing large datasets!
