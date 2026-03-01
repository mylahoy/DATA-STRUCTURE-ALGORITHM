# TaskMate - Flask Backend

from flask import Flask, render_template, request, jsonify
from typing import Any
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Security: Secret key for sessions
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

DB_FILE = 'database.json'

# Type definitions
UserDict = dict[str, str]
Database = dict[str, list[UserDict]]

def init_db() -> None:
    """Initialize database file if it doesn't exist"""
    if not os.path.exists(DB_FILE):
        default_data: Database = {
            "pending": [],
            "approved": [{"username": "admin", "email": "admin@system.com", "password": generate_password_hash("admin123")}]
        }
        with open(DB_FILE, 'w') as f:
            json.dump(default_data, f)

init_db()

def read_db() -> Database:
    """Read database from file"""
    try:
        with open(DB_FILE, 'r') as f:
            data: Any = json.load(f)
            return data if isinstance(data, dict) else {"pending": [], "approved": []}  # type: ignore[return-value]
    except (json.JSONDecodeError, FileNotFoundError):
        return {"pending": [], "approved": []}

def write_db(data: Database) -> None:
    """Write database to file"""
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# Routes
@app.route('/')
def index() -> str:
    return render_template('logreg.html')

@app.route('/dashboard')
def dashboard() -> str:
    return render_template('dashboard.html')

@app.route('/login', methods=['POST'])
def login() -> Any:
    data: Any = request.json
    username: str = str(data.get('username', '')) if data else ''
    password: str = str(data.get('password', '')) if data else ''
    is_admin: bool = bool(data.get('isAdmin', False)) if data else False
    admin_pin: str = str(data.get('pin', '')) if data else ''

    if is_admin:
        admin_pin_expected: str = os.environ.get('ADMIN_PIN', '9999')
        if username == "admin" and password == "admin123" and admin_pin == admin_pin_expected:
            return jsonify({"redirect": "/dashboard", "status": "success"})
        return jsonify({"message": "Invalid Admin Credentials or PIN", "status": "error"}), 401

    db: Database = read_db()
    approved_users: list[UserDict] = db.get('approved', [])
    user: UserDict | None = next((u for u in approved_users if u.get('username') == username), None)
    
    if user:
        stored_password: str = str(user.get('password', ''))
        if check_password_hash(stored_password, password):
            return jsonify({"message": f"Welcome {username}!", "status": "success"})
        return jsonify({"message": "Invalid password", "status": "error"}), 401
    
    pending_users: list[UserDict] = db.get('pending', [])
    pending: UserDict | None = next((u for u in pending_users if u.get('username') == username), None)
    if pending:
        return jsonify({"message": "Account pending approval.", "status": "error"}), 401
        
    return jsonify({"message": "User not found.", "status": "error"}), 404

@app.route('/register', methods=['POST'])
def register() -> Any:
    data: Any = request.json
    db: Database = read_db()
    username: str = str(data.get('username', '')) if data else ''
    
    all_users: list[UserDict] = db.get('pending', []) + db.get('approved', [])
    if any(u.get('username') == username for u in all_users):
        return jsonify({"message": "Username already taken.", "status": "error"}), 400
    
    password: str = str(data.get('password', '')) if data else ''
    new_user: UserDict = {
        "username": username,
        "email": str(data.get('email', '')) if data else '',
        "password": generate_password_hash(password)
    }
    
    if 'pending' not in db:
        db['pending'] = []
    db['pending'].append(new_user)
    write_db(db)
    return jsonify({"message": "Registration sent! Waiting for admin approval.", "status": "success"})

@app.route('/get_requests')
def get_requests() -> Any:
    return jsonify(read_db().get('pending', []))

@app.route('/get_users')
def get_users() -> Any:
    return jsonify(read_db().get('approved', []))

@app.route('/get_stats')
def get_stats() -> Any:
    db: Database = read_db()
    return jsonify({
        "pending_count": len(db.get('pending', [])),
        "approved_count": len(db.get('approved', []))
    })

@app.route('/approve', methods=['POST'])
def approve() -> Any:
    data: Any = request.json
    username: str = str(data.get('username', '')) if data else ''
    db: Database = read_db()
    
    pending_users: list[UserDict] = db.get('pending', [])
    user_data: UserDict | None = next((u for u in pending_users if u.get('username') == username), None)
    
    if user_data:
        db['pending'].remove(user_data)
        if 'approved' not in db:
            db['approved'] = []
        db['approved'].append(user_data)
        write_db(db)
        return jsonify({"message": f"Approved {username}!"})
    return jsonify({"message": "User not found"}), 404

@app.route('/reject', methods=['POST'])
def reject() -> Any:
    data: Any = request.json
    username: str = str(data.get('username', '')) if data else ''
    db: Database = read_db()
    
    pending_users: list[UserDict] = db.get('pending', [])
    user_data: UserDict | None = next((u for u in pending_users if u.get('username') == username), None)
    
    if user_data:
        db['pending'].remove(user_data)
        write_db(db)
        return jsonify({"message": f"Rejected {username}'s registration request."})
    return jsonify({"message": "User not found"}), 404

@app.route('/edit_user', methods=['POST'])
def edit_user() -> Any:
    data: Any = request.json
    username: str = str(data.get('username', '')) if data else ''
    new_email: str = str(data.get('email', '')) if data else ''
    new_username: str = str(data.get('new_username', '')) if data else ''
    db: Database = read_db()
    
    approved_users: list[UserDict] = db.get('approved', [])
    user_data: UserDict | None = next((u for u in approved_users if u.get('username') == username), None)
    
    if not user_data:
        return jsonify({"message": "User not found"}), 404
    
    if new_username and new_username != username:
        if any(u.get('username') == new_username for u in approved_users):
            return jsonify({"message": "Username already taken"}), 400
        user_data['username'] = new_username
    
    if new_email:
        user_data['email'] = new_email
    
    write_db(db)
    return jsonify({"message": f"Updated user {username}"})

@app.route('/reset_password', methods=['POST'])
def reset_password() -> Any:
    data: Any = request.json
    username: str = str(data.get('username', '')) if data else ''
    new_password: str = str(data.get('new_password', '')) if data else ''
    db: Database = read_db()
    
    if username == 'admin':
        return jsonify({"message": "Cannot reset admin password this way"}), 400
    
    approved_users: list[UserDict] = db.get('approved', [])
    user_data: UserDict | None = next((u for u in approved_users if u.get('username') == username), None)
    
    if user_data:
        user_data['password'] = generate_password_hash(new_password)
        write_db(db)
        return jsonify({"message": f"Password reset for {username}"})
    return jsonify({"message": "User not found"}), 404

@app.route('/delete_user', methods=['POST'])
def delete_user() -> Any:
    data: Any = request.json
    username: str = str(data.get('username', '')) if data else ''
    db: Database = read_db()
    
    if username == 'admin':
        return jsonify({"message": "Cannot delete admin account"}), 400
    
    approved_users: list[UserDict] = db.get('approved', [])
    user_data: UserDict | None = next((u for u in approved_users if u.get('username') == username), None)
    
    if user_data:
        db['approved'].remove(user_data)
        write_db(db)
        return jsonify({"message": f"Deleted user {username}!"})
    return jsonify({"message": "User not found"}), 404

if __name__ == '__main__':
    app.run(debug=True)

