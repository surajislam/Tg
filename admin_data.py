# admin_data.py
import json
import os
import fcntl
import threading
import time
import random
import string
from datetime import datetime
from datetime import timedelta

class AdminDataManager:
    def __init__(self):
        self.data_file = 'admin_database.json'
        self._lock = threading.Lock()
        self.data = {}
        self.init_database()
        
        # Admin Login Credentials (Hardcoded for simplicity)
        self.ADMIN_USERNAME = "admin"
        self.ADMIN_PASSWORD = "admin123"

        # Coupon Codes (For unlimited access)
        # Key: Coupon Code | Value: { 'is_active': True/False, 'access_days': 30 (or None for lifetime) }
        self.COUPON_CODES = {
            "UNLTD999": {'is_active': True, 'access_days': 30},
            "FREEMASS": {'is_active': True, 'access_days': 7},
            "LIFETIME": {'is_active': True, 'access_days': None} 
        }

    def generate_hash_code(self):
        """Generate a unique 12-digit alphanumeric hash code"""
        characters = string.ascii_uppercase + string.digits
        return ''.join(random.choices(characters, k=12))

    def init_database(self):
        """Initialize database with default demo data"""
        if not os.path.exists(self.data_file):
            admin_hash = "ADMIN9999RSX" 

            default_data = {
                "users": [
                    {
                        "id": 1,
                        "name": "Admin User",
                        "hash_code": admin_hash,
                        "balance": 9999,
                        "is_unlimited": False, 
                        "unlimited_expiry": None, # <--- Added expiry field
                        "created_at": datetime.now().isoformat()
                    }
                ],
                "demo_usernames": [
                    {
                        "id": 1,
                        "username": "riyakhanna1",
                        "mobile_number": "7091729147",
                        "mobile_details": "👤 Sattar shah, 📞 917091729147, 🗺️ BIHAR JIO",
                        "active": True,
                        "created_at": datetime.now().isoformat()
                    }
                ],
                "valid_utrs": [
                    {
                        "id": 1,
                        "utr": "453983442711",
                        "description": "Valid UTR for demo deposits",
                        "active": True,
                        "created_at": datetime.now().isoformat()
                    }
                ],
                "searched_usernames": [], # <--- NEW FIELD: Log of not found searches
                "custom_message": "You have just added balance, please wait for 2 minutes for search"
            }

            self.save_data(default_data)
        else:
            data = self.load_data()
            updated = False
            
            # Ensure all required top-level keys exist
            if 'users' not in data: data['users'] = []; updated = True
            if 'demo_usernames' not in data: data['demo_usernames'] = []; updated = True
            if 'valid_utrs' not in data: data['valid_utrs'] = []; updated = True
            if 'searched_usernames' not in data: data['searched_usernames'] = []; updated = True # New check
            if 'custom_message' not in data: 
                data['custom_message'] = "You have just added balance, please wait for 2 minutes for search"; updated = True

            # Ensure all required user fields exist
            for user in data['users']:
                if 'is_unlimited' not in user:
                    user['is_unlimited'] = False
                    updated = True
                if 'unlimited_expiry' not in user: # New expiry check
                    user['unlimited_expiry'] = None
                    updated = True

            if updated:
                self.save_data(data)

    def load_data(self):
        """Load data from JSON file with file locking"""
        max_retries = 5
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                with self._lock:
                    with open(self.data_file, 'r') as f:
                        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                        try:
                            self.data = json.load(f)
                            # Ensure defaults on load
                            if 'users' not in self.data: self.data['users'] = []
                            if 'demo_usernames' not in self.data: self.data['demo_usernames'] = []
                            if 'valid_utrs' not in self.data: self.data['valid_utrs'] = []
                            if 'searched_usernames' not in self.data: self.data['searched_usernames'] = []
                            if 'custom_message' not in self.data: 
                                self.data['custom_message'] = "You have just added balance, please wait for 2 minutes for search"

                            # Ensure 'is_unlimited' and 'unlimited_expiry' are present
                            for user in self.data['users']:
                                if 'is_unlimited' not in user: user['is_unlimited'] = False
                                if 'unlimited_expiry' not in user: user['unlimited_expiry'] = None
                            return self.data
                        finally:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except (FileNotFoundError, json.JSONDecodeError):
                if attempt == 0:  
                    self.init_database()
                    continue
                raise
            except (OSError, IOError) as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                raise

        raise Exception("Failed to load data after maximum retries")

    def save_data(self, data=None):
        """Save data to JSON file with file locking and atomic writes"""
        max_retries = 5
        retry_delay = 0.1
        temp_file = self.data_file + '.tmp'

        if data is None:
            data_to_save = self.data
        else:
            data_to_save = data
            self.data = data 

        for attempt in range(max_retries):
            try:
                with self._lock:
                    with open(temp_file, 'w') as f:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        try:
                            json.dump(data_to_save, f, indent=2)
                            f.flush()
                            os.fsync(f.fileno())
                        finally:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

                    os.replace(temp_file, self.data_file)
                    return
            except (OSError, IOError) as e:
                if os.path.exists(temp_file):
                    try: os.remove(temp_file)
                    except: pass

                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                raise

        raise Exception("Failed to save data after maximum retries")

    # --- Utility Methods ---
    def is_unlimited_active(self, user):
        """Check if user's unlimited access is active"""
        if user.get('is_unlimited', False) and user.get('unlimited_expiry') is None:
            return True # Lifetime access

        expiry_str = user.get('unlimited_expiry')
        if expiry_str:
            expiry_dt = datetime.fromisoformat(expiry_str)
            if datetime.now() < expiry_dt:
                return True
            else:
                # Unlimited access expired, reset status and save
                user['is_unlimited'] = False
                user['unlimited_expiry'] = None
                self.save_data() # Save the change
                return False
        return False


    # --- User Management ---
    def create_user(self, name):
        """Create a new user with hash code"""
        data = self.load_data()

        while True:
            hash_code = self.generate_hash_code()
            if not any(user['hash_code'] == hash_code for user in data['users']):
                break

        new_id = max([user['id'] for user in data['users']], default=0) + 1
        new_user = {
            "id": new_id,
            "name": name,
            "hash_code": hash_code,
            "balance": 0,
            "is_unlimited": False, 
            "unlimited_expiry": None, 
            "created_at": datetime.now().isoformat()
        }

        data['users'].append(new_user)
        self.save_data(data)
        return new_user

    def get_users(self):
        """Get all users, resetting expired unlimited access"""
        data = self.load_data()
        for user in data['users']:
            # This ensures status is updated even when just viewing the dashboard
            self.is_unlimited_active(user) 
        return data['users']

    def get_user_by_hash(self, hash_code):
        """Get user by hash code and check unlimited status"""
        data = self.load_data()
        for user in data['users']:
            if user['hash_code'] == hash_code:
                # Ensure latest status check
                if self.is_unlimited_active(user):
                    # If unlimited, ensure balance is high (visual/logic fallback)
                    user['balance'] = 99999999 
                return user
        return None

    def update_user_balance(self, hash_code, new_balance):
        """Update user balance"""
        data = self.load_data()
        found = False
        for user in data['users']:
            if user['hash_code'] == hash_code:
                user['balance'] = new_balance
                found = True
                break
        
        if found:
            self.save_data(data)
            return True
        return False

    def grant_unlimited_access(self, hash_code, access_days=None):
        """Grants unlimited access."""
        data = self.load_data()
        found = False
        for user in data['users']:
            if user['hash_code'] == hash_code:
                user['is_unlimited'] = True
                user['balance'] = 99999999 # Set high balance
                
                if access_days is None:
                    # Lifetime access
                    user['unlimited_expiry'] = None
                else:
                    # Timed access
                    expiry_dt = datetime.now() + timedelta(days=access_days)
                    user['unlimited_expiry'] = expiry_dt.isoformat()

                found = True
                break

        if found:
            self.save_data(data)
            return True
        return False
        
    def deduct_balance(self, hash_code, amount=1):
        """Deduct balance if not unlimited"""
        data = self.load_data()
        for user in data['users']:
            if user['hash_code'] == hash_code:
                if self.is_unlimited_active(user):
                    return True # Unlimited users do not need deduction
                    
                if user['balance'] >= amount:
                    user['balance'] -= amount
                    self.save_data(data)
                    return True
                else:
                    return False # Insufficient balance
        return False

    def delete_user(self, user_id):
        """Delete user"""
        data = self.load_data()
        data['users'] = [user for user in data['users'] if user['id'] != int(user_id)]
        self.save_data(data)

    # --- Search Data Management ---
    def get_usernames(self):
        data = self.load_data()
        return data['demo_usernames']
        
    def find_demo_username(self, username):
        """Find a match in demo usernames"""
        data = self.load_data()
        for item in data['demo_usernames']:
            if item['username'].lower() == username.lower():
                return item
        return None

    def log_searched_username(self, username, user_hash):
        """Log username that was searched but not found"""
        data = self.load_data()
        
        # Check if already logged in the last 7 days (or implement your desired logic)
        for item in data['searched_usernames']:
            if item['username'].lower() == username.lower():
                # Update timestamp if already exists
                item['searched_at'] = datetime.now().isoformat()
                self.save_data(data)
                return

        new_id = max([item['id'] for item in data['searched_usernames']], default=0) + 1
        new_entry = {
            "id": new_id,
            "username": username,
            "searched_by_hash": user_hash,
            "searched_at": datetime.now().isoformat(),
            "status": "Not Found" # Can be used for tracking in dashboard
        }
        data['searched_usernames'].append(new_entry)
        self.save_data(data)

    def get_searched_usernames(self):
        """Get all logged searched usernames"""
        data = self.load_data()
        return data.get('searched_usernames', [])
        
    def get_statistics(self):
        """Get database statistics"""
        self.load_data()
        return {
            'users': len(self.data.get('users', [])),
            'usernames': len(self.data.get('demo_usernames', [])),
            'utrs': len(self.data.get('valid_utrs', [])),
            'searched': len(self.data.get('searched_usernames', []))
        }

    # --- UTR CRUD and Custom Message (Same as before) ---

    def get_utrs(self):
        data = self.load_data()
        return data['valid_utrs']

    def add_utr(self, utr, description):
        data = self.load_data()
        new_id = max([item['id'] for item in data['valid_utrs']], default=0) + 1
        new_utr = {
            "id": new_id,
            "utr": utr,
            "description": description,
            "active": True,
            "created_at": datetime.now().isoformat()
        }
        data['valid_utrs'].append(new_utr)
        self.save_data(data)
        return new_utr

    def delete_utr(self, utr_id):
        data = self.load_data()
        data['valid_utrs'] = [item for item in data['valid_utrs'] if item['id'] != int(utr_id)]
        self.save_data(data)

    def get_custom_message(self):
        self.load_data()
        return self.data.get('custom_message', "You have just added balance, please wait for 2 minutes for search")

    def update_custom_message(self, message):
        self.load_data()
        self.data['custom_message'] = message.strip()
        self.save_data()
        return True


# Global instance
admin_db = AdminDataManager()

# Configuration for App.py
ADMIN_USERNAME = admin_db.ADMIN_USERNAME
ADMIN_PASSWORD = admin_db.ADMIN_PASSWORD
COUPON_CODES = admin_db.COUPON_CODES
