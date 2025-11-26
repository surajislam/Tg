#App.py coad update kardo full



# App.py (Complete Final Code)
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from datetime import datetime
import os
import time

# Ensure admin_data.py is in the same directory
try:
    from admin_data import admin_db, ADMIN_USERNAME, ADMIN_PASSWORD, COUPON_CODES
except ImportError:
    print("Error: admin_data.py not found. Please ensure it's in the same directory.")
    exit()

app = Flask(__name__)
app.secret_key = os.urandom(24) # Production ke liye strong secret key use karein

# Configuration
SEARCH_COST = 1 # Per search cost

# --- USER FACING ROUTES (index.html) ---

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Hash Code Login Logic
        user_hash = request.form.get('user_hash', '').strip()

        user = admin_db.get_user_by_hash(user_hash)

        if user:
            session['user_hash'] = user_hash
            flash(f'Welcome back, {user["name"]}! Your balance is ₹{user["balance"]}.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid Hash Code. Please try again.', 'error')

    # Data for GET Request/Rendering
    user = None
    if 'user_hash' in session:
        user = admin_db.get_user_by_hash(session['user_hash'])
        if not user:
             session.pop('user_hash', None)
             flash('Your session expired or hash is invalid.', 'error')
             return redirect(url_for('index'))

    # Prepare message for the user panel
    custom_message = admin_db.get_custom_message()

    return render_template('index.html', user=user, custom_message=custom_message, search_cost=SEARCH_COST)

@app.route('/logout')
def user_logout():
    session.pop('user_hash', None)
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/check_utr', methods=['POST'])
def check_utr():
    if 'user_hash' not in session:
        return jsonify({'success': False, 'message': 'Session expired. Please log in again.'})

    utr = request.json.get('utr', '').strip()

    if not utr:
        return jsonify({'success': False, 'message': 'Please enter a UTR number.'})

    valid_utrs = admin_db.get_utrs()

    is_valid = any(item['utr'] == utr for item in valid_utrs)

    if is_valid:
        # In a real system, you would add balance here and delete the UTR.
        # For this demo, we just return success.
        return jsonify({'success': True, 'message': 'Payment successful! Your balance will be credited soon.'})
    else:
        return jsonify({'success': False, 'message': 'Invalid UTR/Transaction ID. Please check and try again.'})


@app.route('/apply_coupon', methods=['POST'])
def apply_coupon():
    if 'user_hash' not in session:
        return jsonify({'success': False, 'error': 'Session expired. Please log in again.'}), 401

    coupon_code = request.json.get('coupon_code', '').strip().upper()
    user_hash = session['user_hash']

    if coupon_code in COUPON_CODES:
        coupon_data = COUPON_CODES[coupon_code]

        if coupon_data['is_active']:
            access_days = coupon_data['access_days']

            # Grant unlimited access logic in admin_data.py
            if admin_db.grant_unlimited_access(user_hash, access_days):
                if access_days is None:
                    expiry_msg = 'Lifetime'
                else:
                    expiry_dt = datetime.now() + timedelta(days=access_days)
                    expiry_msg = expiry_dt.strftime('%d %b %Y')

                return jsonify({
                    'success': True, 
                    'message': f'Coupon "{coupon_code}" applied successfully! You now have Unlimited access until {expiry_msg}.'
                })
            else:
                return jsonify({'success': False, 'error': 'User not found or database error.'})
        else:
            return jsonify({'success': False, 'error': 'This coupon code is inactive.'})
    else:
        return jsonify({'success': False, 'error': 'Invalid coupon code.'})


@app.route('/search', methods=['POST'])
def search_username():
    if 'user_hash' not in session:
        return jsonify({'success': False, 'error': 'Session expired. Please log in again.'}), 401

    user_hash = session['user_hash']
    username = request.json.get('username', '').strip().replace('@', '')

    if not username:
        return jsonify({'success': False, 'error': 'Please enter a Telegram username.'})

    user = admin_db.get_user_by_hash(user_hash)

    if not user:
        session.pop('user_hash', None)
        return jsonify({'success': False, 'error': 'Invalid user session. Please re-login.'}), 401

    # Check Unlimited status first
    is_unlimited = admin_db.is_unlimited_active(user)

    # 1. Deduct Balance (Only if not unlimited)
    if not is_unlimited:
        if not admin_db.deduct_balance(user_hash, SEARCH_COST):
            return jsonify({'success': False, 'error': f'Insufficient balance. Search costs ₹{SEARCH_COST}. Your current balance is ₹{user["balance"]}.'})

    # 2. Search for the username in the demo database
    match = admin_db.find_demo_username(username)

    if match:
        # Found
        # Get the latest balance after deduction for the response
        updated_user = admin_db.get_user_by_hash(user_hash)

        return jsonify({
            'success': True,
            'found': True,
            'result': match['mobile_details'], # Send the stored details
            'new_balance': updated_user['balance'],
            'is_unlimited': is_unlimited
        })
    else:
        # Not Found
        # 3. Log the search and return custom message
        admin_db.log_searched_username(username, user_hash)

        # Get the latest balance after deduction
        updated_user = admin_db.get_user_by_hash(user_hash)

        return jsonify({
            'success': True,
            'found': False,
            'message': admin_db.get_custom_message(),
            'new_balance': updated_user['balance'],
            'is_unlimited': is_unlimited
        })


# --- ADMIN ROUTES ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid Admin Credentials.', 'error')

    return render_template('Admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out successfully.', 'success')
    return redirect(url_for('admin_login_page'))


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash('Please log in to access the admin panel.', 'error')
        return redirect(url_for('admin_login_page'))

    # Data fetch karke template ko bhejna
    stats = admin_db.get_statistics()
    users = admin_db.get_users()
    usernames = admin_db.get_usernames()
    utrs = admin_db.get_utrs()
    custom_message = admin_db.get_custom_message()
    searched = admin_db.get_searched_usernames()

    return render_template('admin_dashboard.html', 
                           stats=stats, 
                           users=users, 
                           usernames=usernames, 
                           utrs=utrs, 
                           custom_message=custom_message,
                           searched=searched)


# --- API/Action Routes for Admin Dashboard (Used by admin.js) ---

@app.route('/admin/users/create', methods=['POST'])
def admin_create_user():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    data = request.get_json()
    name = data.get('name')
    if not name: return jsonify({'success': False, 'error': 'Name is required'}), 400
    new_user = admin_db.create_user(name)
    return jsonify({'success': True, 'user': new_user})

@app.route('/admin/users/delete', methods=['POST'])
def admin_delete_user():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    user_id = request.get_json().get('user_id')
    admin_db.delete_user(user_id)
    return jsonify({'success': True})

@app.route('/admin/users/update_balance', methods=['POST'])
def admin_update_balance():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    data = request.get_json()
    hash_code = data.get('hash_code')
    new_balance = data.get('new_balance')
    if not hash_code or new_balance is None: return jsonify({'success': False, 'error': 'Missing data'}), 400
    if admin_db.update_user_balance(hash_code, new_balance):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'User not found'}), 404

@app.route('/admin/users/grant_unlimited', methods=['POST'])
def admin_grant_unlimited():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    hash_code = request.get_json().get('hash_code')
    # Grant lifetime access (None days)
    if admin_db.grant_unlimited_access(hash_code, access_days=None):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'User not found or update failed'}), 404


@app.route('/admin/data/add_username', methods=['POST'])
def admin_add_username():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    data = request.get_json()
    username = data.get('username')
    mobile_number = data.get('mobile_number')
    mobile_details = data.get('mobile_details')
    if not all([username, mobile_number, mobile_details]): return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    new_user = admin_db.add_username(username, mobile_number, mobile_details)
    return jsonify({'success': True, 'username': new_user['username']})

@app.route('/admin/data/update_username', methods=['POST'])
def admin_update_username():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    data = request.get_json()
    username_id = data.get('username_id')
    username = data.get('username')
    mobile_number = data.get('mobile_number')
    mobile_details = data.get('mobile_details')
    if not all([username_id, username, mobile_number, mobile_details]): return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    try:
        admin_db.update_username(username_id, username, mobile_number, mobile_details)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/data/delete_username', methods=['POST'])
def admin_delete_username():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    username_id = request.get_json().get('username_id')
    if not username_id: return jsonify({'success': False, 'error': 'Missing ID'}), 400
    admin_db.delete_username(username_id)
    return jsonify({'success': True})

@app.route('/admin/utr/add', methods=['POST'])
def admin_add_utr():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    data = request.get_json()
    utr = data.get('utr')
    description = data.get('description')
    if not utr or not description: return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    new_utr = admin_db.add_utr(utr, description)
    return jsonify({'success': True, 'utr': new_utr['utr']})

@app.route('/admin/utr/delete', methods=['POST'])
def admin_delete_utr():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    utr_id = request.get_json().get('utr_id')
    if not utr_id: return jsonify({'success': False, 'error': 'Missing ID'}), 400
    admin_db.delete_utr(utr_id)
    return jsonify({'success': True})

@app.route('/admin/settings/get_message', methods=['GET'])
def admin_get_message():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    message = admin_db.get_custom_message()
    return jsonify({'success': True, 'message': message})

@app.route('/admin/settings/update_message', methods=['POST'])
def admin_update_message():
    if not session.get('admin_logged_in'): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    message = request.get_json().get('message')
    if message is None: return jsonify({'success': False, 'error': 'Message field is missing'}), 400
    admin_db.update_custom_message(message)
    return jsonify({'success': True})


if __name__ == '__main__':
    print("Initializing Database...")
    admin_db.init_database()
    print(f"Admin Username: {ADMIN_USERNAME}, Admin Password: {ADMIN_PASSWORD}")
    # app.run() line ko hata diya gaya hai

    # Start the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)