#!/usr/bin/env python3
"""
Telegram Username Search Web App
Web-based interface for Telegram username search with hash code authentication
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import hashlib
import time
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect, validate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from admin_data import admin_db
from searched_usernames import searched_username_manager

app = Flask(__name__)
# Use environment variable for secret key with secure fallback
app.secret_key = os.environ.get('FLASK_SECRET_KEY', '93ad4012d376e47c78e3cdab59f81ceba23c65bbdc1e34560f0b6da01a79d2b8')

# Configure session cookies for mobile compatibility
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Allow HTTP for development/Replit
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to cookies
    SESSION_COOKIE_SAMESITE='None',  # Allow cross-site requests for mobile
    PERMANENT_SESSION_LIFETIME=1800  # 30 minutes session timeout
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Enable CORS for all routes (mobile compatibility)
CORS(app, resources={
    r'/*': {
        'origins': '*',
        'methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        'allow_headers': ['Content-Type', 'Authorization', 'X-Requested-With'],
        'supports_credentials': False
    }
})

# Mobile-friendly configurations
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True



# Add OPTIONS handler for mobile browsers
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = app.make_response("")
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response


# Admin credentials
ADMIN_CREDENTIALS = {
    'rxprime': os.environ.get('ADMIN_PASSWORD_HASH_1', generate_password_hash('rxprime'))
}

class TelegramUserSearch:
    def __init__(self, bot_token=None):
        """
        Demo search functionality
        """
        self.bot_token = bot_token or os.getenv('8528924905:AAEQS3DGCubbX8cs-JGloy5AhDU-MxA7mtI')

    def search_public_info(self, username):
        """
        Search for username in demo database
        """
        if username.startswith('@'):
            username = username[1:]

        # Get demo usernames from database
        demo_usernames = admin_db.get_usernames()

        # Search for specific username in database (case insensitive)
        username_lower = username.lower()

        for user_data in demo_usernames:
            if user_data['active'] and user_data['username'].lower() == username_lower:
                return {
                    "success": True,
                    "user_data": {
                        "username": user_data['username'],
                        "mobile_number": user_data['mobile_number'],
                        "mobile_details": user_data['mobile_details']
                    }
                }

        # User not found in database - store in searched usernames
        return {
            "success": False,
            "error": "No details available in the database"
        }

# Initialize searcher
searcher = TelegramUserSearch()

@app.route('/')
def home():
    """Main page - check authentication and redirect appropriately"""
    if not session.get('authenticated'):
        return redirect(url_for('login_page'))
    return redirect(url_for('dashboard'))

@app.route('/login')
def login_page():
    """Login/Signup page"""
    if session.get('authenticated'):
        return redirect(url_for('home'))

    response = app.make_response(render_template('login.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

@app.route('/signup', methods=['POST'])
@csrf.exempt
def signup():
    """Handle user registration"""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()

        if not name or len(name) < 2:
            return jsonify({
                'success': False,
                'error': 'Please enter a valid name (at least 2 characters)'
            })

        # Create new user
        new_user = admin_db.create_user(name)

        return jsonify({
            'success': True,
            'message': 'Account created successfully!',
            'hash_code': new_user['hash_code'],
            'name': new_user['name']
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Registration error occurred'
        })

@app.route('/login', methods=['POST'])
@csrf.exempt
def login():
    """Handle login authentication"""
    try:
        data = request.get_json()
        hash_code = data.get('hash_code', '').strip()

        if not hash_code:
            return jsonify({
                'success': False,
                'error': 'Please enter your hash code'
            })

        # Check if user exists
        user = admin_db.get_user_by_hash(hash_code)
        if user:
            session['authenticated'] = True
            session['user_hash'] = hash_code
            session['user_name'] = user['name']
            session['user_balance'] = user['balance']
            return jsonify({
                'success': True,
                'message': f'Welcome back, {user["name"]}!'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid hash code. Please check and try again.'
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Authentication error occurred'
        })

@app.route('/dashboard')
def dashboard():
    """Main search dashboard"""
    if not session.get('authenticated'):
        session.clear()
        return redirect(url_for('login_page'))

    user_hash = session.get('user_hash')
    user = admin_db.get_user_by_hash(user_hash)
    balance = user['balance'] if user else 0

    response = app.make_response(render_template('index.html',
                                               balance=balance,
                                               user_name=session.get('user_name')))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/search', methods=['POST'])
@csrf.exempt
def search():
    """Username search API endpoint - Cost: ₹30 per search"""
    # Check authentication
    if not session.get('authenticated'):
        return jsonify({
            'error': 'Authentication required',
            'success': False
        }), 401

    try:
        data = request.get_json()
        username = data.get('username', '').strip()

        if not username:
            return jsonify({
                "error": "Username enter kariye",
                "success": False
            })

        # Get current user balance
        user_hash = session.get('user_hash')
        user = admin_db.get_user_by_hash(user_hash)
        current_balance = user['balance'] if user else 0

        # Check balance for search cost (₹30)
        if current_balance < 30:
            return jsonify({
                "error": "Insufficient balance. You need ₹30 for this search. Please deposit money to continue.",
                "success": False
            })

        # Professional 10-second delay
        time.sleep(10)

        # Search perform karte hain
        result = searcher.search_public_info(username)

        if result and result.get('success'):
            # Deduct ₹30 from balance for successful search
            new_balance = current_balance - 30
            admin_db.update_user_balance(user_hash, new_balance)
            session['user_balance'] = new_balance
            result['new_balance'] = new_balance
        else:
            # User not found - store in searched usernames file
            searched_username_manager.add_searched_username(username, user_hash)
            custom_message = admin_db.get_custom_message()
            result = {
                "success": False,
                "error": custom_message
            }

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "error": f"Server error: {str(e)}",
            "success": False
        })

@app.route('/deposit', methods=['POST'])
def deposit():
    """Handle deposit requests with UTR verification"""
    # Check authentication
    if not session.get('authenticated'):
        return jsonify({
            'error': 'Authentication required',
            'success': False
        }), 401

    try:
        data = request.get_json()
        utr = data.get('utr', '').strip()
        amount = data.get('amount', 0)

        if not utr:
            return jsonify({
                'error': 'UTR number is required',
                'success': False
            })

        if amount not in [60, 90, 120, 900, 1800]:
            return jsonify({
                'error': 'Invalid amount selected',
                'success': False
            })

        # Check if UTR is valid from database
        valid_utrs = admin_db.get_utrs()
        valid_utr_numbers = [utr_data['utr'] for utr_data in valid_utrs if utr_data['active']]

        if utr in valid_utr_numbers:
            # Add amount to balance
            user_hash = session.get('user_hash')
            user = admin_db.get_user_by_hash(user_hash)
            current_balance = user['balance'] if user else 0
            new_balance = current_balance + amount
            admin_db.update_user_balance(user_hash, new_balance)
            session['user_balance'] = new_balance

            return jsonify({
                'success': True,
                'message': 'Balance successfully added',
                'new_balance': new_balance,
                'amount_added': amount
            })
        else:
            return jsonify({
                'error': 'Wrong UTR number. Please check your payment and enter the correct UTR.',
                'success': False
            })

    except Exception as e:
        return jsonify({
            'error': f'Server error: {str(e)}',
            'success': False
        })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "app": "Telegram Username Search with Hash Code Auth",
        "version": "2.0"
    })

# ===== ADMIN PANEL ROUTES =====

@app.route('/admin/login')
def admin_login_page():
    """Admin login page"""
    return render_template('admin_login.html')

@app.route('/admin/login', methods=['POST'])
@csrf.exempt
def admin_login():
    """Handle admin authentication"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username and password required'
            })

        # Check admin credentials
        if username in ADMIN_CREDENTIALS and check_password_hash(ADMIN_CREDENTIALS[username], password):
            session['admin_authenticated'] = True
            session['admin_username'] = username
            return jsonify({
                'success': True,
                'message': 'Admin access granted'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid admin credentials'
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Authentication error occurred'
        })

@app.route('/admin/logout', methods=['POST'])
@csrf.exempt
def admin_logout():
    """Handle admin logout"""
    session.pop('admin_authenticated', None)
    session.pop('admin_username', None)
    return jsonify({'success': True})

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard page"""
    if not session.get('admin_authenticated'):
        return redirect(url_for('admin_login_page'))
    from flask_wtf.csrf import generate_csrf
    return render_template('admin_dashboard.html', csrf_token=generate_csrf)

# Admin API Routes
@app.route('/admin/api/statistics')
def admin_statistics():
    """Get statistics for admin dashboard"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        stats = {
            'users': len(admin_db.get_users()),
            'usernames': len(admin_db.get_usernames()),
            'utrs': len(admin_db.get_utrs())
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Users CRUD (Replace Access Codes)
@app.route('/admin/api/users')
def admin_get_users():
    """Get all users"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(admin_db.get_users())

@app.route('/admin/api/users/<int:user_id>', methods=['DELETE'])
@csrf.exempt
def admin_delete_user(user_id):
    """Delete user"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        admin_db.delete_user(user_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Usernames CRUD (Updated)
@app.route('/admin/api/usernames')
def admin_get_usernames():
    """Get all demo usernames"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(admin_db.get_usernames())

@app.route('/admin/api/usernames/<int:user_id>')
def admin_get_username(user_id):
    """Get single username"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    usernames = admin_db.get_usernames()
    for username in usernames:
        if username['id'] == user_id:
            return jsonify(username)
    return jsonify({'error': 'Not found'}), 404

@app.route('/admin/api/usernames', methods=['POST'])
@csrf.exempt
def admin_add_username():
    """Add new demo username"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        mobile_number = data.get('mobile_number', '').strip()
        mobile_details = data.get('mobile_details', '').strip()

        if not username or not mobile_number:
            return jsonify({'success': False, 'error': 'Username and mobile number required'})

        new_user = admin_db.add_username(username, mobile_number, mobile_details)
        return jsonify({'success': True, 'data': new_user})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/api/usernames/<int:user_id>', methods=['PUT'])
@csrf.exempt
def admin_update_username(user_id):
    """Update demo username"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        mobile_number = data.get('mobile_number', '').strip()
        mobile_details = data.get('mobile_details', '').strip()

        admin_db.update_username(user_id, username, mobile_number, mobile_details)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/api/usernames/<int:user_id>', methods=['DELETE'])
@csrf.exempt
def admin_delete_username(user_id):
    """Delete demo username"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        admin_db.delete_username(user_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# UTRs CRUD (Keep existing)
@app.route('/admin/api/utrs')
def admin_get_utrs():
    """Get all UTRs"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(admin_db.get_utrs())

@app.route('/admin/api/utrs', methods=['POST'])
@csrf.exempt
def admin_add_utr():
    """Add new UTR"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        utr = data.get('utr', '').strip()
        description = data.get('description', '').strip()

        new_utr = admin_db.add_utr(utr, description)
        return jsonify({'success': True, 'data': new_utr})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/api/utrs/<int:utr_id>', methods=['DELETE'])
@csrf.exempt
def admin_delete_utr(utr_id):
    """Delete UTR"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        admin_db.delete_utr(utr_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Balance Update API
@app.route('/admin/api/users/balance', methods=['POST'])
@csrf.exempt
def admin_update_balance():
    """Update user balance"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        hash_code = data.get('hash_code')
        new_balance = data.get('new_balance')

        if not hash_code or new_balance is None:
            return jsonify({'success': False, 'error': 'Hash code and balance required'})

        admin_db.update_user_balance(hash_code, new_balance)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Balance Addition API
@app.route('/admin/api/users/<int:user_id>/add-balance', methods=['POST'])
@csrf.exempt
def admin_add_user_balance(user_id):
    """Add balance to user account"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        amount = data.get('amount', 0)

        if amount <= 0:
            return jsonify({'success': False, 'error': 'Amount must be greater than 0'})

        # Get user by ID
        users = admin_db.get_users()
        user_found = None
        for user in users:
            if user['id'] == user_id:
                user_found = user
                break

        if not user_found:
            return jsonify({'success': False, 'error': 'User not found'})

        # Update balance
        new_balance = user_found['balance'] + amount
        admin_db.update_user_balance(user_found['hash_code'], new_balance)
        
        return jsonify({'success': True, 'new_balance': new_balance})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Custom Message API
@app.route('/admin/api/custom-message')
def admin_get_custom_message():
    """Get custom not found message"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    return jsonify({'message': admin_db.get_custom_message()})

@app.route('/admin/api/custom-message', methods=['PUT'])
@csrf.exempt
def admin_update_custom_message():
    """Update custom not found message"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        message = data.get('message', '').strip()

        if not message:
            return jsonify({'success': False, 'error': 'Message cannot be empty'})

        admin_db.update_custom_message(message)
        return jsonify({'success': True, 'message': 'Custom message updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Searched Usernames API
@app.route('/admin/api/searched-usernames')
def admin_get_searched_usernames():
    """Get all searched usernames that were not found"""
    if not session.get('admin_authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401

    return jsonify(searched_username_manager.get_searched_usernames())

def create_app():
    return app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))

    if os.environ.get('REPLIT_DEPLOYMENT') or os.environ.get('PRODUCTION'):
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
    else:
        debug_mode = os.environ.get('FLASK_ENV') != 'production'
        app.run(host='0.0.0.0', port=port, debug=debug_mode, threaded=True)