import os
import json
import requests
import pandas as pd
from datetime import datetime, timedelta
import time
import logging
from flask import Flask, request, render_template, redirect, url_for, jsonify, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import io
import sys

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.info("Starting app.py execution")

app = Flask(__name__)
logger.info("Flask app initialized")

# Database configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'


def load_settings():
    """Load settings from database"""
    try:
        settings = {}
        app_settings = AppSettings.query.all()

        for setting in app_settings:
            if '.' in setting.key:
                # Nested settings like defaults.days
                keys = setting.key.split('.')
                if keys[0] not in settings:
                    settings[keys[0]] = {}
                settings[keys[0]][keys[1]] = setting.value
            else:
                # Simple settings
                try:
                    # Try to parse as JSON for complex data like accounts array
                    settings[setting.key] = json.loads(setting.value)
                except (json.JSONDecodeError, TypeError):
                    settings[setting.key] = setting.value

        logger.info("Settings loaded from database successfully")
        return settings
    except Exception as e:
        logger.error(f"Error loading settings from database: {str(e)}")
        return None

def save_settings(settings):
    """Save settings to database"""
    try:
        # Clear existing settings
        AppSettings.query.delete()

        # Save new settings
        for key, value in settings.items():
            if isinstance(value, dict):
                # Handle nested settings
                for sub_key, sub_value in value.items():
                    setting = AppSettings(key=f"{key}.{sub_key}", value=str(sub_value))
                    db.session.add(setting)
            else:
                # Handle simple settings
                if isinstance(value, (list, dict)):
                    setting_value = json.dumps(value)
                else:
                    setting_value = str(value)
                setting = AppSettings(key=key, value=setting_value)
                db.session.add(setting)

        db.session.commit()
        logger.info("Settings saved to database successfully")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving settings to database: {str(e)}")

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class AppSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize database and create default data
def init_db():
    """Initialize database and create default data"""
    with app.app_context():
        db.create_all()

        # Create default admin user if no users exist
        if User.query.count() == 0:
            admin_user = User(username='admin')
            admin_user.set_password(os.environ.get('ADMIN_PASSWORD', 'admin123'))
            db.session.add(admin_user)

            # Create default settings
            default_settings = {
                'accounts': '[]',
                'active_account': '',
                'defaults.days': '10',
                'defaults.direction': 'Sent',
                'defaults.status': '',
                'defaults.page_size': '100',
                'defaults.data_folder': 'data'
            }

            for key, value in default_settings.items():
                setting = AppSettings(key=key, value=value)
                db.session.add(setting)

            db.session.commit()
            logger.info("Database initialized with default admin user and settings")

# Initialize database
init_db()

def get_token(acc):
    logger.info(f"Attempting to get token for account: {acc.get('name')}")
    data = {
        'grant_type': 'client_credentials',
        'client_id': acc['client_id'],
        'client_secret': acc['client_secret']
    }
    if acc.get('scope'):
        data['scope'] = acc['scope']
    headers = {}
    if acc.get('on_behalf_of'):
        headers['on_behalf_of'] = acc['on_behalf_of']
    try:
        resp = requests.post(acc['token_url'], data=data, headers=headers)
        if resp.status_code == 200:
            logger.info("Token retrieved successfully")
            return resp.json()['access_token']
        else:
            logger.error(f"Authentication failed: {resp.status_code} - {resp.text}")
            raise Exception(f"Authentication failed: {resp.text}")
    except Exception as e:
        logger.error(f"Exception during authentication: {str(e)}")
        raise

def fetch_detail(token, base_url, uuid, data_folder):
    detail_dir = os.path.join(data_folder, 'details')
    os.makedirs(detail_dir, exist_ok=True)
    detail_file = os.path.join(detail_dir, f'{uuid}.json')
    logger.info(f"Checking detail file: {detail_file}")
    if not os.path.exists(detail_file):
        if not token or not base_url:
            logger.error(f"Cannot fetch details for UUID {uuid}: missing token or base_url")
            return {}
        url = base_url + f'documents/{uuid}/details'
        headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                try:
                    det = resp.json()
                    json.dumps(det, ensure_ascii=False)  # Validate JSON
                    logger.info(f"Raw API response for UUID {uuid}: {json.dumps(det)[:200]}...")
                    with open(detail_file, 'w', encoding='utf-8') as f:
                        json.dump(det, f, indent=4, ensure_ascii=False)
                    logger.info(f"Successfully fetched and saved details for UUID: {uuid}")
                    return det
                except ValueError as e:
                    logger.error(f"Invalid JSON response for UUID {uuid}: {str(e)}")
                    with open(detail_file, 'w', encoding='utf-8') as f:
                        json.dump({}, f)
                    return {}
            else:
                logger.error(f"Error fetching details for UUID {uuid}: {resp.status_code} - {resp.text}")
                return {}
        except requests.exceptions.RequestException as e:
            logger.error(f"Exception fetching details for UUID {uuid}: {str(e)}")
            return {}
    else:
        try:
            with open(detail_file, 'r', encoding='utf-8') as f:
                det = json.load(f)
            logger.info(f"Loaded existing details for UUID {uuid}: {json.dumps(det)[:200]}...")
            return det
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error reading detail file for UUID {uuid}: {str(e)}")
            return {}

@app.errorhandler(404)
def page_not_found(e):
    logger.info("404 error occurred")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 error occurred: {str(e)}")
    return render_template('500.html'), 500

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please provide both username and password.', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@login_manager.unauthorized_handler
def unauthorized():
    flash('You must be logged in to access this page.', 'warning')
    return redirect(url_for('login'))

@app.route('/test')
def test_route():
    logger.info("Test route accessed")
    return jsonify({"message": "Flask server is running!"})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    logger.info("Accessing settings page")
    settings = load_settings()
    if settings is None:
        return render_template('500.html', error="Failed to load settings.")
    if request.method == 'POST':
        action = request.form.get('action')
        logger.info(f"Settings action: {action}")
        if action == 'add_account':
            new_acc = {
                'name': request.form['name'],
                'client_id': request.form['client_id'],
                'client_secret': request.form['client_secret'],
                'on_behalf_of': request.form.get('on_behalf_of', ''),
                'token_url': request.form['token_url'],
                'base_url': request.form['base_url'],
                'scope': request.form.get('scope', '')
            }
            settings['accounts'].append(new_acc)
        elif action == 'edit_account':
            index = int(request.form['index'])
            settings['accounts'][index] = {
                'name': request.form['name'],
                'client_id': request.form['client_id'],
                'client_secret': request.form['client_secret'],
                'on_behalf_of': request.form.get('on_behalf_of', ''),
                'token_url': request.form['token_url'],
                'base_url': request.form['base_url'],
                'scope': request.form.get('scope', '')
            }
        elif action == 'delete_account':
            index = int(request.form['index'])
            del settings['accounts'][index]
            if settings['active_account'] == request.form['name']:
                settings['active_account'] = None if not settings['accounts'] else settings['accounts'][0]['name']
        elif action == 'set_active':
            settings['active_account'] = request.form['active_account']
        elif action == 'set_defaults':
            settings['defaults'] = {
                'days': int(request.form['days']),
                'direction': request.form['direction'],
                'status': request.form['status'],
                'page_size': int(request.form['page_size']),
                'data_folder': request.form['data_folder']
            }
        save_settings(settings)
        return redirect(url_for('settings_page'))
    return render_template('settings.html', settings=settings)

@app.route('/sync')
@login_required
def sync():
    logger.info("Starting sync process")
    settings = load_settings()
    if settings is None:
        return render_template('500.html', error="Failed to load settings."), 500
    if not settings['active_account']:
        return render_template('500.html', error="No active account selected."), 400
    acc = next((a for a in settings['accounts'] if a['name'] == settings['active_account']), None)
    if not acc:
        return render_template('500.html', error="Active account not found."), 400
    try:
        token = get_token(acc)
    except Exception as e:
        return render_template('500.html', error=f"Authentication failed: {str(e)}"), 401
    days = settings['defaults']['days']
    direction = settings['defaults']['direction']
    status = settings['defaults']['status']
    page_size = settings['defaults']['page_size']
    data_folder = settings['defaults']['data_folder']
    os.makedirs(data_folder, exist_ok=True)
    docs_file = os.path.join(data_folder, 'documents.csv')
    existing_df = pd.read_csv(docs_file) if os.path.exists(docs_file) else pd.DataFrame()
    existing_uuids = set(existing_df['uuid']) if not existing_df.empty else set()
    new_docs = []
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    chunk_days = 10
    current_start = start_date
    while current_start < end_date:
        current_end = min(current_start + timedelta(days=chunk_days), end_date)
        from_str = current_start.isoformat(timespec='seconds') + 'Z'
        to_str = current_end.isoformat(timespec='seconds') + 'Z'
        page = 1
        while True:
            params = {
                'submissionDateFrom': from_str,
                'submissionDateTo': to_str,
                'direction': direction,
                'status': status if status else None,
                'pageNo': page,
                'pageSize': page_size
            }
            url = acc['base_url'] + 'documents/recent'
            headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
            logger.info(f"Request URL: {url} with params: {params}")
            try:
                resp = requests.get(url, headers=headers, params={k: v for k, v in params.items() if v is not None})
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error: {str(e)}")
                return render_template('500.html', error=f"Connection error: {str(e)}"), 500
            if resp.status_code != 200:
                logger.error(f"API error: {resp.status_code} - {resp.text}")
                return render_template('500.html', error=f"API error: {resp.text}"), resp.status_code
            data = resp.json()
            logger.info(f"API Response: {json.dumps(data, indent=2)}")
            docs = data.get('result', [])
            for doc in docs:
                if doc.get('uuid') not in existing_uuids:
                    new_docs.append(doc)
                    existing_uuids.add(doc['uuid'])
                    if doc.get('status') == 'Invalid':
                        fetch_detail(token, acc['base_url'], doc['uuid'], data_folder)
            metadata = data.get('metadata', {})
            if page >= metadata.get('totalPages', 1):
                break
            page += 1
            time.sleep(1)  # Throttle
        current_start = current_end
        time.sleep(1)  # Throttle between chunks
    if new_docs:
        new_df = pd.DataFrame(new_docs)
        updated_df = pd.concat([existing_df, new_df], ignore_index=True)
        updated_df.to_csv(docs_file, index=False)
    logger.info("Sync completed, redirecting to dashboard")
    return redirect(url_for('dashboard'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    logger.info("Accessing dashboard")
    settings = load_settings()
    if settings is None:
        return render_template('500.html', error="Failed to load settings.")
    data_folder = settings['defaults']['data_folder']
    docs_file = os.path.join(data_folder, 'documents.csv')

    # Handle missing or empty data gracefully
    if not os.path.exists(docs_file):
        logger.info("documents.csv not found - showing empty dashboard")
        df = pd.DataFrame()
    else:
        try:
            df = pd.read_csv(docs_file)
        except Exception as e:
            logger.error(f"Error reading documents.csv: {str(e)}")
            df = pd.DataFrame()

    # If no data, show empty dashboard instead of error
    if df.empty:
        logger.info("No documents found - showing empty dashboard")
        # Return empty dashboard with zero counts
        totals = {'total': 0, 'valid': 0, 'invalid': 0, 'submitted': 0, 'cancelled': 0}
        table_data = []
        available_columns = []
        status_options = []
        date_options = []
        return render_template('dashboard.html', totals=totals, table_data=table_data,
                              available_columns=available_columns, status_options=status_options,
                              date_options=date_options, status_filter='', date_filter='',
                              from_date='', to_date='', active_account='No Active Account')

    logger.info(f"DataFrame columns: {df.columns.tolist()}")
    
    # Apply filters
    filtered_df = df.copy()

    # Only apply filters if this is a POST request (form submission)
    if request.method == 'POST':
        status_filter = request.form.get('status_filter', '')
        date_filter = request.form.get('date_filter', '')
        from_date = request.form.get('from_date', '')
        to_date = request.form.get('to_date', '')
    else:
        status_filter = ''
        date_filter = ''
        from_date = ''
        to_date = ''


    if status_filter:
        filtered_df = filtered_df[filtered_df['status'] == status_filter]

    if date_filter:
        try:
            filtered_df['date'] = pd.to_datetime(filtered_df['dateTimeReceived']).dt.date.astype(str)
            filtered_df = filtered_df[filtered_df['date'] == date_filter]
        except Exception as e:
            logger.error(f"Error processing date filter: {str(e)}")

    # Apply date range filters
    if from_date or to_date:
        try:
            # Convert dateTimeReceived to date for comparison
            filtered_df['submission_date'] = pd.to_datetime(filtered_df['dateTimeReceived']).dt.date

            if from_date:
                from_date_obj = pd.to_datetime(from_date).date()
                filtered_df = filtered_df[filtered_df['submission_date'] >= from_date_obj]

            if to_date:
                to_date_obj = pd.to_datetime(to_date).date()
                filtered_df = filtered_df[filtered_df['submission_date'] <= to_date_obj]

        except Exception as e:
            logger.error(f"Error processing date range filters: {str(e)}")
    
    # Totals
    total_docs = len(filtered_df)
    valid = len(filtered_df[filtered_df['status'] == 'Valid'])
    invalid = len(filtered_df[filtered_df['status'] == 'Invalid'])
    submitted = len(filtered_df[filtered_df['status'] == 'Submitted'])
    cancelled = len(filtered_df[filtered_df['status'] == 'Cancelled'])
    totals = {'total': total_docs, 'valid': valid, 'invalid': invalid, 'submitted': submitted, 'cancelled': cancelled}
    logger.info(f"Submitted documents count: {submitted}")
    
    # Table data with reordered columns
    columns = ['internalId', 'uuid', 'dateTimeReceived', 'dateTimeValidated', 'status', 'typeName', 'typeVersionName', 'submissionUID', 'supplierName', 'buyerName', 'total', 'longId', 'submissionChannel']
    available_columns = [col for col in columns if col in df.columns]
    table_data = filtered_df[available_columns].to_dict(orient='records')
    
    # Filter options
    status_options = df['status'].unique().tolist() if 'status' in df.columns else []
    date_options = df['dateTimeReceived'].apply(lambda x: pd.to_datetime(x).date().isoformat()).unique().tolist() if 'dateTimeReceived' in df.columns else []
    
    logger.info("Rendering dashboard template")
    return render_template('dashboard.html', totals=totals, table_data=table_data,
                          available_columns=available_columns, status_options=status_options,
                          date_options=date_options, status_filter=status_filter,
                          date_filter=date_filter, from_date=from_date, to_date=to_date,
                          active_account=settings.get('active_account', 'No Active Account'))

@app.route('/export_csv', methods=['POST'])
@login_required
def export_csv():
    logger.info("Exporting CSV")
    settings = load_settings()
    if settings is None:
        return jsonify({'error': 'Failed to load settings'}), 500
    data_folder = settings['defaults']['data_folder']
    docs_file = os.path.join(data_folder, 'documents.csv')
    if not os.path.exists(docs_file):
        logger.info("documents.csv not found for export - returning empty CSV")
        # Return empty CSV with headers
        output = io.StringIO()
        output.write("No data available\n")
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='documents_empty.csv'
        )

    try:
        df = pd.read_csv(docs_file)
    except Exception as e:
        logger.error(f"Error reading documents.csv for export: {str(e)}")
        return jsonify({'error': 'Error reading data'}), 500
    
    status_filter = request.form.get('status_filter', '')
    date_filter = request.form.get('date_filter', '')
    if status_filter:
        df = df[df['status'] == status_filter]
    if date_filter:
        df['date'] = pd.to_datetime(df['dateTimeReceived']).dt.date.astype(str)
        df = df[df['date'] == date_filter]
    
    columns = ['internalId', 'uuid', 'dateTimeReceived', 'dateTimeValidated', 'status', 'typeName', 'typeVersionName', 'submissionUID', 'supplierName', 'buyerName', 'total', 'longId', 'submissionChannel']
    available_columns = [col for col in columns if col in df.columns]
    df = df[available_columns]
    
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    logger.info("CSV export successful")
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='documents_export.csv'
    )

@app.route('/retry_detail/<uuid>')
def retry_detail(uuid):
    logger.info(f"Retrying detail fetch for UUID: {uuid}")
    settings = load_settings()
    if settings is None:
        return jsonify({'error': 'Failed to load settings'}), 500
    acc = next((a for a in settings['accounts'] if a['name'] == settings['active_account']), None)
    if not acc:
        logger.error("No active account found")
        return jsonify({'error': 'No active account'}), 400
    data_folder = settings['defaults']['data_folder']
    detail_file = os.path.join(data_folder, 'details', f'{uuid}.json')
    if os.path.exists(detail_file):
        try:
            os.remove(detail_file)
            logger.info(f"Deleted existing detail file: {detail_file}")
        except Exception as e:
            logger.error(f"Error deleting detail file: {str(e)}")
    try:
        token = get_token(acc)
        det = fetch_detail(token, acc['base_url'], uuid, data_folder)
        logger.info(f"Retry successful for UUID: {uuid}")
        return redirect(url_for('detail', uuid=uuid))
    except Exception as e:
        logger.error(f"Retry failed for UUID {uuid}: {str(e)}")
        return render_template('500.html', error=f"Error retrying details: {str(e)}"), 500

@app.route('/detail/<uuid>')
@login_required
def detail(uuid):
    logger.info(f"Accessing detail page for UUID: {uuid}")
    settings = load_settings()
    if settings is None:
        return render_template('500.html', error="Failed to load settings."), 500
    data_folder = settings['defaults']['data_folder']
    acc = next((a for a in settings['accounts'] if a['name'] == settings['active_account']), None)
    if not acc:
        logger.error("No active account found")
        return render_template('500.html', error="No active account."), 400
    detail_file = os.path.join(data_folder, 'details', f'{uuid}.json')
    if not os.path.exists(detail_file):
        try:
            token = get_token(acc)
            det = fetch_detail(token, acc['base_url'], uuid, data_folder)
        except Exception as e:
            logger.error(f"Error fetching details: {str(e)}")
            return render_template('detail.html', uuid=uuid, val_status='Unknown', error_count=0, warning_count=0, raw_json='{}')
    else:
        det = fetch_detail(None, None, uuid, data_folder)  # Load from file
    try:
        val_status = det.get('validationResults', {}).get('status', 'Unknown')
        steps = det.get('validationResults', {}).get('validationSteps', [])
        error_count = sum(1 for s in steps if s.get('status') == 'Invalid')
        warning_count = 0  # No explicit warnings in API
        raw_json = json.dumps(det, indent=4, ensure_ascii=False) if det else '{}'
        logger.info(f"Detail data for UUID {uuid}: {raw_json[:200]}...")
        return render_template('detail.html', uuid=uuid, val_status=val_status, error_count=error_count, warning_count=warning_count, raw_json=raw_json)
    except Exception as e:
        logger.error(f"Error preparing detail data for UUID {uuid}: {str(e)}")
        return render_template('detail.html', uuid=uuid, val_status='Unknown', error_count=0, warning_count=0, raw_json='{}')

if __name__ == '__main__':
    print("Starting Flask server...")
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting Flask server on port {port}")
    try:
        # Production mode - no debug
        app.run(host='0.0.0.0', port=port, debug=False)
    except Exception as e:
        logger.error(f"Error starting Flask server: {str(e)}")
        print(f"Error starting Flask server: {str(e)}")