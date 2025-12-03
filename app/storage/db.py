import mysql.connector
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# --- Database Configuration ---
# Use your local MariaDB credentials
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USER', 'chat_app_user')
DB_PASS = os.environ.get('DB_PASS', '123Password') # Your password
DB_NAME = os.environ.get('DB_NAME', 'secure_chat')

def get_db_connection():
    """Establishes a new database connection."""
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None

def init_db():
    """Creates the 'users' table if it doesn't exist."""
    conn = get_db_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    
    # Assignment Requirement: users table
    # email VARCHAR, username VARCHAR UNIQUE, salt VARBINARY(16), pwd_hash CHAR(64)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        salt VARBINARY(16) NOT NULL,
        pwd_hash CHAR(64) NOT NULL
    );
    """)
    print("Database initialized. 'users' table is ready.")
    conn.commit()
    cursor.close()
    conn.close()

def hash_password(password, salt):
    """Hashes a password with the given salt."""
    # Assignment Requirement: pwd_hash = hex(SHA256(salt || password))
    # We will concatenate and hash
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(salt)
    hasher.update(password.encode('utf-8'))
    pwd_hash = hasher.finalize()
    
    # Return the hex representation of the hash
    return pwd_hash.hex()

def register_user(email, username, password):
    """Registers a new user with a salted password hash."""
    
    # Assignment Requirement: Generate a 16-byte random salt
    salt = os.urandom(16)
    
    # Hash the password
    pwd_hash = hash_password(password, salt)
    
    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"
        
    cursor = conn.cursor()
    try:
        # Store email, username, salt, and the hex hash
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        print(f"User '{username}' registered successfully.")
        return True, "User registered successfully"
    except mysql.connector.Error as err:
        # Check for duplicate email/username
        if err.errno == 1062: # Duplicate entry
            return False, "Email or username already exists"
        return False, f"Database error: {err}"
    finally:
        cursor.close()
        conn.close()

def verify_user(email, password):
    """Verifies a user's email and password for login."""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"
    
    cursor = conn.cursor(dictionary=True) # Fetch as dict
    
    try:
        cursor.execute("SELECT salt, pwd_hash FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if not user:
            return False, "User not found"
            
        # Re-compute the hash using the stored salt and provided password
        stored_salt = user['salt']
        stored_hash = user['pwd_hash']
        
        computed_hash = hash_password(password, stored_salt)
        
        # Assignment Requirement: constant-time compare
        # This checks if the hashes match
        if computed_hash == stored_hash:
            print(f"User '{email}' authenticated successfully.")
            return True, "Login successful"
        else:
            return False, "Invalid password"
            
    except mysql.connector.Error as err:
        return False, f"Database error: {err}"
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    # This block allows us to run 'python -m app.storage.db' to set up the table
    print("Initializing database...")
    init_db()