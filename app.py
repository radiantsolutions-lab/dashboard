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
        logger.info(f"Loading {len(app_settings)} settings from database")

        for setting in app_settings:
            logger.info(f"Loading setting: {setting.key} = {setting.value}")
            if '.' in setting.key:
                # Nested settings like defaults.days
                keys = setting.key.split('.')
                if keys[0] not in settings:
                    settings[keys[0]] = {}

                # Convert numeric values for defaults
                if keys[0] == 'defaults':
                    if keys[1] in ['days', 'page_size']:
                        try:
                            settings[keys[0]][keys[1]] = int(setting.value)
                        except (ValueError, TypeError):
                            settings[keys[0]][keys[1]] = 10 if keys[1] == 'days' else 100
                    else:
                        settings[keys[0]][keys[1]] = setting.value
                else:
                    settings[keys[0]][keys[1]] = setting.value
            else:
                # Simple settings
                try:
                    # Try to parse as JSON for complex data like accounts array
                    settings[setting.key] = json.loads(setting.value)
                except (json.JSONDecodeError, TypeError):
                    settings[setting.key] = setting.value

        logger.info(f"Settings loaded successfully: {settings}")
        return settings
    except Exception as e:
        logger.error(f"Error loading settings from database: {str(e)}")
        return None

def save_settings(settings):
    """Save settings to database"""
    try:
        logger.info(f"Saving settings: {settings}")
        # Clear existing settings
        AppSettings.query.delete()

        # Save new settings
        for key, value in settings.items():
            if isinstance(value, dict):
                # Handle nested settings
                for sub_key, sub_value in value.items():
                    setting_key = f"{key}.{sub_key}"
                    setting_value = str(sub_value)
                    logger.info(f"Saving setting: {setting_key} = {setting_value}")
                    setting = AppSettings(key=setting_key, value=setting_value)
                    db.session.add(setting)
            else:
                # Handle simple settings
                if isinstance(value, (list, dict)):
                    setting_value = json.dumps(value)
                else:
                    setting_value = str(value)
                logger.info(f"Saving setting: {key} = {setting_value}")
                setting = AppSettings(key=key, value=setting_value)
                db.session.add(setting)

        db.session.commit()
        logger.info("Settings saved to database successfully")

        # Verify what was saved
        saved_settings = AppSettings.query.all()
        logger.info(f"Verified saved settings: {[(s.key, s.value) for s in saved_settings]}")

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

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(100), unique=True, nullable=False, index=True)
    submission_uid = db.Column(db.String(100), index=True)
    long_id = db.Column(db.String(200))
    internal_id = db.Column(db.String(100))
    type_name = db.Column(db.String(100))
    type_version_name = db.Column(db.String(50))
    supplier_tin = db.Column(db.String(50))
    supplier_name = db.Column(db.String(200))
    receiver_tin = db.Column(db.String(50))
    issuer_tin = db.Column(db.String(50))
    receiver_name = db.Column(db.String(200))
    date_time_issued = db.Column(db.DateTime)
    date_time_received = db.Column(db.DateTime, index=True)
    date_time_validated = db.Column(db.DateTime)
    total_sales = db.Column(db.Float)
    total_discount = db.Column(db.Float)
    net_amount = db.Column(db.Float)
    total = db.Column(db.Float)
    status = db.Column(db.String(50), index=True)
    submission_channel = db.Column(db.String(50))
    intermediary_name = db.Column(db.String(200))
    intermediary_tin = db.Column(db.String(50))
    intermediary_rob = db.Column(db.String(50))
    submitter_rob = db.Column(db.String(50))
    cancel_date_time = db.Column(db.DateTime)
    reject_request_date_time = db.Column(db.DateTime)
    document_status_reason = db.Column(db.Text)
    created_by_user_id = db.Column(db.String(50))
    buyer_name = db.Column(db.String(200))
    buyer_tin = db.Column(db.String(50))
    receiver_id = db.Column(db.String(50))
    receiver_id_type = db.Column(db.String(50))
    issuer_id = db.Column(db.String(50))
    issuer_id_type = db.Column(db.String(50))
    document_currency = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class DocumentDetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(100), nullable=False, index=True)
    detail_data = db.Column(db.Text, nullable=False)  # JSON data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (db.Index('idx_uuid', 'uuid'),)

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

# Helper functions for data conversion
def parse_datetime(date_str):
    """Parse datetime string, return None if invalid"""
    if not date_str:
        return None
    try:
        return pd.to_datetime(date_str)
    except:
        return None

def float_or_none(value):
    """Convert to float, return None if invalid"""
    if value is None or value == '':
        return None
    try:
        return float(value)
    except:
        return None

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

def fetch_detail(token, base_url, uuid, data_folder=None):
    """Fetch document details from API or database"""
    logger.info(f"Checking document details for UUID: {uuid}")

    # Check if details exist in database
    existing_detail = DocumentDetail.query.filter_by(uuid=uuid).first()
    if existing_detail:
        try:
            det = json.loads(existing_detail.detail_data)
            logger.info(f"Loaded existing details for UUID {uuid} from database")
            return det
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Error parsing stored detail data for UUID {uuid}: {str(e)}")

    # Fetch from API if not in database
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

                # Save to database
                try:
                    # Remove existing detail if any
                    if existing_detail:
                        db.session.delete(existing_detail)

                    # Create new detail record
                    detail_record = DocumentDetail(
                        uuid=uuid,
                        detail_data=json.dumps(det, ensure_ascii=False)
                    )
                    db.session.add(detail_record)
                    db.session.commit()
                    logger.info(f"Successfully fetched and saved details for UUID: {uuid}")
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error saving document detail to database: {str(e)}")

                return det
            except ValueError as e:
                logger.error(f"Invalid JSON response for UUID {uuid}: {str(e)}")
                return {}
        else:
            logger.error(f"Error fetching details for UUID {uuid}: {resp.status_code} - {resp.text}")
            return {}
    except requests.exceptions.RequestException as e:
        logger.error(f"Exception fetching details for UUID {uuid}: {str(e)}")
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

@app.route('/debug-settings')
@login_required
def debug_settings():
    """Debug endpoint to check current settings"""
    try:
        settings = load_settings()
        return jsonify({
            "settings_loaded": settings is not None,
            "accounts_count": len(settings.get('accounts', [])) if settings else 0,
            "accounts": [{"name": acc.get('name'), "has_client_id": bool(acc.get('client_id')), "has_client_secret": bool(acc.get('client_secret')), "has_token_url": bool(acc.get('token_url')), "has_base_url": bool(acc.get('base_url'))} for acc in settings.get('accounts', [])] if settings else [],
            "active_account": settings.get('active_account') if settings else None,
            "defaults": settings.get('defaults') if settings else {}
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/debug-sync')
@login_required
def debug_sync():
    """Debug endpoint to test sync authentication without running full sync"""
    try:
        settings = load_settings()
        if not settings or not settings.get('active_account'):
            return jsonify({"error": "No active account selected"}), 400

        acc = next((a for a in settings.get('accounts', []) if a.get('name') == settings['active_account']), None)
        if not acc:
            return jsonify({"error": f"Active account '{settings['active_account']}' not found"}), 400

        # Test authentication
        try:
            token = get_token(acc)
            return jsonify({
                "status": "success",
                "account": acc.get('name'),
                "authentication": "successful",
                "token_received": bool(token),
                "ready_for_sync": True
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "account": acc.get('name'),
                "authentication": "failed",
                "error": str(e),
                "ready_for_sync": False
            }), 500

    except Exception as e:
        return jsonify({"error": f"Debug sync failed: {str(e)}"}), 500

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
            active_account_value = request.form['active_account']
            logger.info(f"Setting active account to: '{active_account_value}'")
            logger.info(f"Available accounts: {[acc.get('name') for acc in settings.get('accounts', [])]}")
            settings['active_account'] = active_account_value
            logger.info(f"Active account set successfully. Current settings active_account: '{settings.get('active_account')}'")
            logger.info(f"Full settings after update: {settings}")
        elif action == 'set_defaults':
            settings['defaults'] = {
                'days': int(request.form['days']) if request.form['days'] else 10,
                'direction': request.form['direction'],
                'status': request.form['status'],
                'page_size': int(request.form['page_size']) if request.form['page_size'] else 100
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
        logger.error("Failed to load settings")
        return render_template('500.html', error="Failed to load settings."), 500

    logger.info(f"Active account from settings: '{settings.get('active_account')}'")
    logger.info(f"Available accounts: {[acc.get('name') for acc in settings.get('accounts', [])]}")

    if not settings.get('active_account'):
        logger.error("No active account selected")
        return render_template('500.html', error="No active account selected."), 400

    acc = next((a for a in settings.get('accounts', []) if a.get('name') == settings['active_account']), None)
    if not acc:
        logger.error(f"Active account '{settings['active_account']}' not found in accounts list")
        return render_template('500.html', error="Active account not found."), 400

    logger.info(f"Using account: {acc.get('name')}")
    try:
        token = get_token(acc)
    except Exception as e:
        return render_template('500.html', error=f"Authentication failed: {str(e)}"), 401
    days = int(settings['defaults'].get('days', 10))
    direction = settings['defaults'].get('direction', 'Sent')
    status = settings['defaults'].get('status', '')
    page_size = int(settings['defaults'].get('page_size', 100))
    # Get existing document UUIDs from database
    existing_uuids = set([doc.uuid for doc in Document.query.with_entities(Document.uuid).all()])
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
                        fetch_detail(token, acc['base_url'], doc['uuid'], None)  # No data_folder needed
            metadata = data.get('metadata', {})
            if page >= metadata.get('totalPages', 1):
                break
            page += 1
            time.sleep(1)  # Throttle
        current_start = current_end
        time.sleep(1)  # Throttle between chunks

    # Save new documents to database
    if new_docs:
        logger.info(f"Saving {len(new_docs)} new documents to database")
        for doc_data in new_docs:
            try:
                # Create document record
                document = Document(
                    uuid=doc_data.get('uuid'),
                    submission_uid=doc_data.get('submissionUid'),
                    long_id=doc_data.get('longId'),
                    internal_id=doc_data.get('internalId'),
                    type_name=doc_data.get('typeName'),
                    type_version_name=doc_data.get('typeVersionName'),
                    supplier_tin=doc_data.get('supplierTIN'),
                    supplier_name=doc_data.get('supplierName'),
                    receiver_tin=doc_data.get('receiverTIN'),
                    issuer_tin=doc_data.get('issuerTIN'),
                    receiver_name=doc_data.get('receiverName'),
                    date_time_issued=parse_datetime(doc_data.get('dateTimeIssued')),
                    date_time_received=parse_datetime(doc_data.get('dateTimeReceived')),
                    date_time_validated=parse_datetime(doc_data.get('dateTimeValidated')),
                    total_sales=float_or_none(doc_data.get('totalSales')),
                    total_discount=float_or_none(doc_data.get('totalDiscount')),
                    net_amount=float_or_none(doc_data.get('netAmount')),
                    total=float_or_none(doc_data.get('total')),
                    status=doc_data.get('status'),
                    submission_channel=doc_data.get('submissionChannel'),
                    intermediary_name=doc_data.get('intermediaryName'),
                    intermediary_tin=doc_data.get('intermediaryTIN'),
                    intermediary_rob=doc_data.get('intermediaryROB'),
                    submitter_rob=doc_data.get('submitterROB'),
                    cancel_date_time=parse_datetime(doc_data.get('cancelDateTime')),
                    reject_request_date_time=parse_datetime(doc_data.get('rejectRequestDateTime')),
                    document_status_reason=doc_data.get('documentStatusReason'),
                    created_by_user_id=doc_data.get('createdByUserId'),
                    buyer_name=doc_data.get('buyerName'),
                    buyer_tin=doc_data.get('buyerTIN'),
                    receiver_id=doc_data.get('receiverID'),
                    receiver_id_type=doc_data.get('receiverIDType'),
                    issuer_id=doc_data.get('issuerID'),
                    issuer_id_type=doc_data.get('issuerIDType'),
                    document_currency=doc_data.get('documentCurrency')
                )
                db.session.add(document)
            except Exception as e:
                logger.error(f"Error creating document record for UUID {doc_data.get('uuid')}: {str(e)}")
                continue

        try:
            db.session.commit()
            logger.info(f"Successfully saved {len(new_docs)} documents to database")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error committing documents to database: {str(e)}")
            return render_template('500.html', error="Failed to save documents to database"), 500

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

    # Get documents from database
    query = Document.query

    # Apply filters
    status_filter = ''
    date_filter = ''
    from_date = ''
    to_date = ''

    if request.method == 'POST':
        status_filter = request.form.get('status_filter', '')
        date_filter = request.form.get('date_filter', '')
        from_date = request.form.get('from_date', '')
        to_date = request.form.get('to_date', '')

        if status_filter:
            query = query.filter(Document.status == status_filter)

        if date_filter:
            try:
                date_obj = pd.to_datetime(date_filter).date()
                query = query.filter(db.func.date(Document.date_time_received) == date_obj)
            except Exception as e:
                logger.error(f"Error processing date filter: {str(e)}")

        # Apply date range filters
        if from_date:
            try:
                from_date_obj = pd.to_datetime(from_date).date()
                query = query.filter(db.func.date(Document.date_time_received) >= from_date_obj)
            except Exception as e:
                logger.error(f"Error processing from_date filter: {str(e)}")

        if to_date:
            try:
                to_date_obj = pd.to_datetime(to_date).date()
                query = query.filter(db.func.date(Document.date_time_received) <= to_date_obj)
            except Exception as e:
                logger.error(f"Error processing to_date filter: {str(e)}")

    # Get filtered documents
    documents = query.all()
    logger.info(f"Found {len(documents)} documents after filtering")

    # If no documents, return empty dashboard
    if not documents:
        logger.info("No documents found - showing empty dashboard")
        totals = {'total': 0, 'valid': 0, 'invalid': 0, 'submitted': 0, 'cancelled': 0}
        table_data = []
        available_columns = []
        status_options = []
        date_options = []
        return render_template('dashboard.html', totals=totals, table_data=table_data,
                              available_columns=available_columns, status_options=status_options,
                              date_options=date_options, status_filter=status_filter, date_filter=date_filter,
                              from_date=from_date, to_date=to_date, active_account=settings.get('active_account', 'No Active Account'))

    # Calculate totals
    total_docs = len(documents)
    valid = len([d for d in documents if d.status == 'Valid'])
    invalid = len([d for d in documents if d.status == 'Invalid'])
    submitted_count = len([d for d in documents if d.status == 'Submitted'])
    cancelled = len([d for d in documents if d.status == 'Cancelled'])
    totals = {'total': total_docs, 'valid': valid, 'invalid': invalid, 'submitted': submitted_count, 'cancelled': cancelled}

    # Table data with selected columns only (UI-friendly display names)
    column_mapping = {
        'Date': 'date_time_validated',
        'Invoice': 'internal_id',
        'UUID': 'uuid',
        'Status': 'status',
        'Type': 'type_name'
    }

    available_columns = list(column_mapping.keys())

    table_data = []
    for doc in documents:
        row = {}
        for display_col, db_col in column_mapping.items():
            value = getattr(doc, db_col, None)
            if db_col in ['date_time_received', 'date_time_validated'] and value:
                # For the Date column, show only date part (YYYY-MM-DD)
                if display_col == 'Date':
                    value = value.strftime('%Y-%m-%d')
                else:
                    value = value.strftime('%Y-%m-%d %H:%M:%S')
            row[display_col] = value or 'N/A'
        table_data.append(row)

    # Filter options
    all_docs = Document.query.all()
    status_options = list(set([d.status for d in all_docs if d.status]))
    date_options = list(set([d.date_time_received.date().isoformat() for d in all_docs if d.date_time_received]))
    
    logger.info("Rendering dashboard template")
    return render_template('dashboard.html', totals=totals, table_data=table_data,
                          available_columns=available_columns, status_options=status_options,
                          date_options=date_options, status_filter=status_filter,
                          date_filter=date_filter, from_date=from_date, to_date=to_date,
                          active_account=settings.get('active_account', 'No Active Account'))

@app.route('/export_csv', methods=['POST'])
@login_required
def export_csv():
    logger.info("Exporting CSV from database")

    # Build query for filtered documents
    query = Document.query

    status_filter = request.form.get('status_filter', '')
    date_filter = request.form.get('date_filter', '')

    if status_filter:
        query = query.filter(Document.status == status_filter)

    if date_filter:
        try:
            date_obj = pd.to_datetime(date_filter).date()
            query = query.filter(db.func.date(Document.date_time_received) == date_obj)
        except Exception as e:
            logger.error(f"Error processing date filter for export: {str(e)}")

    # Get filtered documents
    documents = query.all()
    logger.info(f"Exporting {len(documents)} documents to CSV")

    if not documents:
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

    # Convert to DataFrame for CSV export
    data = []
    for doc in documents:
        row = {
            'internalId': doc.internal_id or '',
            'uuid': doc.uuid,
            'dateTimeReceived': doc.date_time_received.strftime('%Y-%m-%d %H:%M:%S') if doc.date_time_received else '',
            'dateTimeValidated': doc.date_time_validated.strftime('%Y-%m-%d %H:%M:%S') if doc.date_time_validated else '',
            'status': doc.status or '',
            'typeName': doc.type_name or '',
            'typeVersionName': doc.type_version_name or '',
            'submissionUID': doc.submission_uid or '',
            'supplierName': doc.supplier_name or '',
            'buyerName': doc.buyer_name or '',
            'total': str(doc.total) if doc.total is not None else '',
            'longId': doc.long_id or '',
            'submissionChannel': doc.submission_channel or ''
        }
        data.append(row)

    df = pd.DataFrame(data)

    # Export to CSV
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    logger.info("CSV export from database successful")
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

    # Try to get details from database first
    det = fetch_detail(None, None, uuid, None)

    # If not found in database, fetch from API
    if not det:
        acc = next((a for a in settings['accounts'] if a['name'] == settings['active_account']), None)
        if not acc:
            logger.error("No active account found")
            return render_template('500.html', error="No active account."), 400
        try:
            token = get_token(acc)
            det = fetch_detail(token, acc['base_url'], uuid, None)
        except Exception as e:
            logger.error(f"Error fetching details: {str(e)}")
            return render_template('detail.html', uuid=uuid, val_status='Unknown', error_count=0, warning_count=0, raw_json='{}')
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