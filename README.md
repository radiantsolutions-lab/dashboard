# E-Invoice Dashboard

A modern web application for managing e-invoice documents with authentication and PostgreSQL database support.

## 🚀 Deployment on Railway

### Prerequisites
- Railway account
- PostgreSQL database (provided by Railway)

### Environment Variables

Set these environment variables in your Railway project:

```bash
SECRET_KEY=your-very-secure-secret-key-here
ADMIN_PASSWORD=your-admin-password-here
LOG_LEVEL=INFO
```

Railway will automatically provide:
- `DATABASE_URL` - PostgreSQL connection string
- `PORT` - Port for the application

### Deployment Steps

1. **Connect Repository**
   - Connect your GitHub repository to Railway
   - Railway will detect the `railway.json` configuration

2. **Database Setup**
   - Railway provides PostgreSQL automatically
   - The app will create tables on first run

3. **Environment Variables**
   - Set `SECRET_KEY` to a secure random string
   - Set `ADMIN_PASSWORD` to your desired admin password

4. **Deploy**
   - Railway will build and deploy automatically
   - First deployment creates database tables and default admin user

### Default Login Credentials

After deployment, use these credentials:
- **Username:** `admin`
- **Password:** The value you set for `ADMIN_PASSWORD`

### Features

- 🔐 **Secure Authentication** - Flask-Login with password hashing
- 🗄️ **PostgreSQL Database** - User and settings management
- 📊 **Dashboard** - Document overview with filtering
- 🔍 **Advanced Filtering** - Status, date range, and custom filters
- 📱 **Responsive Design** - Modern UI
- 🔄 **Data Sync** - Import documents from external APIs
- 📈 **Analytics** - Document statistics and insights

### Data Management

- Documents are stored as CSV files in the `data/` directory
- Detail JSON files are cached in `data/details/`
- Settings and user data stored in PostgreSQL
- File-based document storage for performance

### API Integration

The application integrates with external e-invoice APIs:
- OAuth2 authentication flow
- Document synchronization
- Validation status checking
- Bulk data import

### Security Features

- Password hashing with PBKDF2
- Session management
- CSRF protection
- Secure headers
- Input validation

## 🛠️ Local Development

```bash
# Clone repository
git clone <repository-url>
cd e-invoice-dashboard

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export SECRET_KEY=your-secret-key
export ADMIN_PASSWORD=your-admin-password
export DATABASE_URL=sqlite:///app.db  # For local SQLite

# Run application
python app.py
```

## 📁 Project Structure

```
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── railway.json          # Railway deployment config
├── templates/            # Jinja2 templates
│   ├── base.html
│   ├── dashboard.html
│   ├── login.html
│   └── ...
├── static/               # Static assets (CSS, JS)
├── data/                 # Document storage
│   ├── documents.csv
│   └── details/
└── README.md
```

## 🔧 Configuration

### Database Models
- `User` - User authentication
- `AppSettings` - Application configuration

### Default Settings
- Sync days: 10
- Direction: RECEIVED
- Status: Valid
- Page size: 100

## 📞 Support

For issues or questions:
1. Check Railway logs
2. Verify environment variables
3. Ensure database connectivity
4. Check file permissions for data directory
