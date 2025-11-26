import json
import os
from datetime import datetime, timedelta
import uuid
import time

# --- CONFIGURATION ---
# CRITICAL FIX (MANDATORY FOR DEPLOYMENT): Database file location must be in the writeable /tmp/ directory.
DB_FILE = '/tmp/admin_data.json'
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123' 

# Example coupon codes (User-facing)
COUPON_CODES = {
    'FREE50': {
        'access_days': 50, # Days of unlimited access
        'is_active': True
    },
    'LIFETIME': {
        'access_days': None, # None means lifetime access
        'is_active': True
    }
}
# --- END CONFIGURATION ---

class AdminDB:
    def __init__(self):
        self._data = self._load_data()

    def _load_data(self):
        # Ensure the parent directory (/tmp/) exists.
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        
        if not os.path.exists(DB_FILE):
            return self._default_data()
        
        try:
            with open(DB_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: {DB_FILE} corrupted. Resetting to default data.")
            return self._default_data()
        except FileNotFoundError:
            return self._default_data()

    def _default_data(self):
        # Default user with hash 'AAAAA' and some balance
        default_user_hash = 'AAAAA'
        
        return {
            'stats': {
                'total_users': 1,
                'total_searches': 0
            },
            'users': {
                default_user_hash: {
                    'id': default_user_hash,
                    'name': 'Default User',
                    'balance': 100,
                    'unlimited_expiry': None, # datetime string or None
                    'created_at': datetime.now().isoformat()
                }
            },
            'usernames': [
                # Example data for searching
                {'id': str(uuid.uuid4()), 'username': 'testuser1', 'mobile_number': '9876543210', 'mobile_details': 'User is active since 2022.'},
                {'id': str(uuid.uuid4()), 'username': 'examplefind', 'mobile_number': '8888888888', 'mobile_details': 'This is a test account detail.'}
            ],
            'utrs': [], # UTRs for payment verification
            'settings': {
                'custom_message': 'No information found for this user. Please try again or check payment details.'
            }
            ,
            'searched_usernames': [] # Log of failed searches
        }

    def _save_data(self):
        with open(DB_FILE, 'w') as f:
            json.dump(self._data, f, indent=4)

    def init_database(self):
        # Database initialization logic
        pass

    # --- User Methods ---

    def get_user_by_hash(self, hash_code):
        user = self._data['users'].get(hash_code)
        if user:
            # Check for unlimited expiry status and update if necessary
            if user['unlimited_expiry'] and user['unlimited_expiry'] != 'lifetime':
                expiry_dt = datetime.fromisoformat(user['unlimited_expiry'])
                if expiry_dt < datetime.now():
                    user['unlimited_expiry'] = None # Expired
                    self._save_data()
            return user
        return None

    def deduct_balance(self, hash_code, amount):
        user = self._data['users'].get(hash_code)
        if user and user['balance'] >= amount:
            user['balance'] -= amount
            self._data['stats']['total_searches'] += 1
            self._save_data()
            return True
        return False
    
    def is_unlimited_active(self, user):
        expiry = user.get('unlimited_expiry')
        if expiry == 'lifetime':
            return True
        if expiry:
            expiry_dt = datetime.fromisoformat(expiry)
            return expiry_dt > datetime.now()
        return False

    def find_demo_username(self, username):
        username_lower = username.lower()
        for item in self._data['usernames']:
            if item['username'].lower() == username_lower:
                return item
        return None
    
    def log_searched_username(self, username, user_hash):
        self._data['searched_usernames'].insert(0, {
            'username': username,
            'user_hash': user_hash,
            'timestamp': datetime.now().isoformat()
        })
        self._save_data()

    def grant_unlimited_access(self, hash_code, access_days):
        user = self._data['users'].get(hash_code)
        if not user:
            return False

        if access_days is None:
            # Lifetime access
            user['unlimited_expiry'] = 'lifetime'
        else:
            # Time-limited access
            new_expiry_date = datetime.now() + timedelta(days=access_days)
            user['unlimited_expiry'] = new_expiry_date.isoformat()
        
        self._save_data()
        return True

    # --- Admin Dashboard Methods ---

    def get_statistics(self):
        users = self._data['users']
        active_unlimited = sum(1 for user in users.values() if self.is_unlimited_active(user))
        
        return {
            'total_users': len(users),
            'total_usernames_in_db': len(self._data['usernames']),
            'total_utrs_pending': len(self._data['utrs']),
            'total_searches_logged': len(self._data['searched_usernames']),
            'active_unlimited_users': active_unlimited
        }
        
    def get_users(self):
        return list(self._data['users'].values())

    def get_usernames(self):
        return self._data['usernames']
    
    def get_utrs(self):
        return self._data['utrs']

    def create_user(self, name):
        new_hash = str(uuid.uuid4())[:5].upper()
        new_user = {
            'id': new_hash,
            'name': name,
            'balance': 0,
            'unlimited_expiry': None,
            'created_at': datetime.now().isoformat()
        }
        self._data['users'][new_hash] = new_user
        self._data['stats']['total_users'] = len(self._data['users'])
        self._save_data()
        return new_user

    def delete_user(self, user_id):
        if user_id in self._data['users']:
            del self._data['users'][user_id]
            self._data['stats']['total_users'] = len(self._data['users'])
            self._save_data()

    def update_user_balance(self, hash_code, new_balance):
        if hash_code in self._data['users']:
            self._data['users'][hash_code]['balance'] = new_balance
            self._save_data()
            return True
        return False

    def add_username(self, username, mobile_number, mobile_details):
        new_entry = {
            'id': str(uuid.uuid4()),
            'username': username,
            'mobile_number': mobile_number,
            'mobile_details': mobile_details
        }
        self._data['usernames'].append(new_entry)
        self._save_data()
        return new_entry

    def update_username(self, username_id, username, mobile_number, mobile_details):
        for item in self._data['usernames']:
            if item['id'] == username_id:
                item['username'] = username
                item['mobile_number'] = mobile_number
                item['mobile_details'] = mobile_details
                self._save_data()
                return
        raise ValueError(f"Username ID {username_id} not found.")

    def delete_username(self, username_id):
        self._data['usernames'] = [item for item in self._data['usernames'] if item['id'] != username_id]
        self._save_data()

    def add_utr(self, utr, description):
        new_utr = {
            'id': str(uuid.uuid4()),
            'utr': utr,
            'description': description,
            'timestamp': datetime.now().isoformat()
        }
        self._data['utrs'].append(new_utr)
        self._save_data()
        return new_utr

    def delete_utr(self, utr_id):
        self._data['utrs'] = [utr for utr in self._data['utrs'] if utr['id'] != utr_id]
        self._save_data()

    def get_custom_message(self):
        return self._data['settings']['custom_message']

    def update_custom_message(self, message):
        self._data['settings']['custom_message'] = message
        self._save_data()

    def get_searched_usernames(self):
        return self._data['searched_usernames']

admin_db = AdminDB()