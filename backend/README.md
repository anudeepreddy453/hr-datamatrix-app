# HR DataMatrix Backend - HR Data Management & Scalability Platform

A Flask-based REST API for managing HR data, succession planning, role management, and advanced analytics with scalable architecture and role-based access control.

## Features

- **User Authentication & Authorization**: JWT-based authentication with role-based access control
- **Role Management**: Create and manage organizational roles with criticality levels
- **Succession Planning**: Track succession plans for critical positions
- **Candidate Management**: Manage potential successors with readiness scores
- **Historical Tracking**: Maintain audit trail of all succession-related actions
- **Advanced Analytics**: Demographic analysis and trend tracking
- **Search Functionality**: Global search across roles and succession plans
- **Scalable Architecture**: Designed to handle 450+ roles efficiently

## Setup

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Environment Configuration**:
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

3. **Run the Application**:
   ```bash
   python app.py
   ```

The API will be available at `http://localhost:5000`

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login

### Roles
- `GET /api/roles` - Get all roles
- `POST /api/roles` - Create new role

### Succession Plans
- `GET /api/succession-plans` - Get succession plans
- `POST /api/succession-plans` - Create succession plan

### Analytics
- `GET /api/analytics/demographics` - Get demographic statistics
- `GET /api/analytics/trends` - Get historical trends

### Search
- `GET /api/search?q=<query>` - Search roles and succession plans

## Database Models

- **User**: Authentication and role management
- **Role**: Organizational positions and criticality
- **SuccessionPlan**: Succession planning data
- **Candidate**: Potential successors
- **HistoricalData**: Audit trail and historical actions

## Default Admin User

Username: `admin`
Password: `admin123`

**Important**: Change these credentials in production!

## Security Features

- Password hashing with bcrypt
- JWT token-based authentication
- Role-based access control
- CORS support for frontend integration
