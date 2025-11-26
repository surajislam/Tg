# App.py (Complete Final Code)
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from datetime import datetime, timedelta
import os

# Ensure admin_data.py is in the same directory
try:
    from admin_data import admin_db, ADMIN_USERNAME, ADMIN_PASSWORD, COUPON_CODES
except ImportError:
    print("Error: admin_data.py not found. Please ensure it's in the same directory.")
    exit()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration
SEARCH_COST = 1  # Per search cost

# --- USER ROUTES ---

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user_hash = request.form.get('user_hash', '').strip()
        user = admin_db.get_user_by_hash(user_hash)

        if user:
            session['user_hash'] = user_hash
            flash(f'Welcome back, {user["name"]}! Your balance is ₹{user["balance"]}.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid Hash Code. Please try again.', 'error')

    user = None
    if 'user_hash' in session:
        user = admin_db.get_user_by_hash(session['user_hash'])
        if not user:
            session.pop('user_hash', None)
            flash('Your session expired or hash is invalid.', 'error')
            return redirect(url_for('index'))

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
        return jsonify({'success': True, 'message': 'Payment successful! Your balance will be credited soon.'})
    else:
        return jsonify({'success': False, 'message': 'Invalid UTR/Transaction ID. Please try again.'})


@app.route('/apply_coupon', methods=['POST'])
def apply_coupon():
    if 'user_hash' not in session:
        return jsonify({'success': False, 'error': 'Session expired.'}), 401

    coupon_code = request.json.get('coupon_code', '').strip().upper()
    user_hash = session['user_hash']

    if coupon_code not in COUPON_CODES:
        return jsonify({'success': False, 'error': 'Invalid coupon code.'})

    coupon_data = COUPON_CODES[coupon_code]

    if not coupon_data['is_active']:
        return jsonify({'success': False, 'error': 'This coupon is inactive.'})

    access_days = coupon_data['access_days']

    if admin_db.grant_unlimited_access(user_hash, access_days):
        if access_days is None:
            expiry_msg = 'Lifetime'
        else:
            expiry_dt = datetime.now() + timedelta(days=access_days)
            expiry_msg = expiry_dt.strftime('%d %b %Y')

        return jsonify({
            'success': True,
            'message': f'Coupon "{coupon_code}" applied! Unlimited access until {expiry_msg}.'
        })

    return jsonify({'success': False, 'error': 'User not found'})


@app.route('/search', methods=['POST'])
def search_username():
    if 'user_hash' not in session:
        return jsonify({'success': False, 'error': 'Session expired.'}), 401

    user_hash = session['user_hash']
    username = request.json.get('username', '').strip().replace('@', '')

    if not username:
        return jsonify({'success': False, 'error': 'Please enter a Telegram username.'})

    user = admin_db.get_user_by_hash(user_hash)

    if not user:
        session.pop('user_hash', None)
        return jsonify({'success': False, 'error': 'Invalid session.'}), 401

    is_unlimited = admin_db.is_unlimited_active(user)

    if not is_unlimited:
        if not admin_db.deduct_balance(user_hash, SEARCH_COST):
            return jsonify({
                'success': False,
                'error': f'Insufficient balance. Search costs ₹{SEARCH_COST}.'
            })

    match = admin_db.find_demo_username(username)

    updated_user = admin_db.get_user_by_hash(user_hash)

    if match:
        return jsonify({
            'success': True,
            'found': True,
            'result': match['mobile_details'],
            'new_balance': updated_user['balance'],
            'is_unlimited': is_unlimited
        })

    admin_db.log_searched_username(username, user_hash)

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
    flash('Admin logged out.', 'success')
    return redirect(url_for('admin_login_page'))


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash('Login required.', 'error')
        return redirect(url_for('admin_login_page'))

    return render_template(
        'admin_dashboard.html',
        stats=admin_db.get_statistics(),
        users=admin_db.get_users(),
        usernames=admin_db.get_usernames(),
        utrs=admin_db.get_utrs(),
        custom_message=admin_db.get_custom_message(),
        searched=admin_db.get_searched_usernames()
    )


# --- ADMIN API ROUTES (Used by admin.js) ---

@app.route('/admin/users/create', methods=['POST'])
def admin_create_user():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    data = request.get_json()
    name = data.get('name')
    new_user = admin_db.create_user(name)
    return jsonify({'success': True, 'user': new_user})


@app.route('/admin/users/delete', methods=['POST'])
def admin_delete_user():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    user_id = request.get_json().get('user_id')
    admin_db.delete_user(user_id)
    return jsonify({'success': True})


@app.route('/admin/users/update_balance', methods=['POST'])
def admin_update_balance():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    data = request.get_json()
    if admin_db.update_user_balance(data['hash_code'], data['new_balance']):
        return jsonify({'success': True})
    return jsonify({'success': False}), 404


@app.route('/admin/users/grant_unlimited', methods=['POST'])
def admin_grant_unlimited():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    if admin_db.grant_unlimited_access(request.get_json().get('hash_code'), None):
        return jsonify({'success': True})
    return jsonify({'success': False}), 404


@app.route('/admin/data/add_username', methods=['POST'])
def admin_add_username():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    data = request.get_json()
    new_user = admin_db.add_username(data['username'], data['mobile_number'], data['mobile_details'])
    return jsonify({'success': True, 'username': new_user['username']})


@app.route('/admin/data/update_username', methods=['POST'])
def admin_update_username():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    data = request.get_json()
    admin_db.update_username(
        data['username_id'], data['username'], data['mobile_number'], data['mobile_details']
    )
    return jsonify({'success': True})


@app.route('/admin/data/delete_username', methods=['POST'])
def admin_delete_username():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    admin_db.delete_username(request.get_json().get('username_id'))
    return jsonify({'success': True})


@app.route('/admin/utr/add', methods=['POST'])
def admin_add_utr():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    data = request.get_json()
    new_utr = admin_db.add_utr(data['utr'], data['description'])
    return jsonify({'success': True, 'utr': new_utr['utr']})


@app.route('/admin/utr/delete', methods=['POST'])
def admin_delete_utr():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    admin_db.delete_utr(request.get_json().get('utr_id'))
    return jsonify({'success': True})


@app.route('/admin/settings/get_message', methods=['GET'])
def admin_get_message():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    return jsonify({'success': True, 'message': admin_db.get_custom_message()})


@app.route('/admin/settings/update_message', methods=['POST'])
def admin_update_message():
    if not session.get('admin_logged_in'): return jsonify({'success': False}), 401
    admin_db.update_custom_message(request.get_json().get('message'))
    return jsonify({'success': True})


# ----------- KOYEB-COMPATIBLE SERVER STARTUP -----------
if __name__ == '__main__':
    print("Initializing Database...")
    admin_db.init_database()
    print(f"Admin Username: {ADMIN_USERNAME}, Admin Password: {ADMIN_PASSWORD}")

    # Koyeb port support
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port)
