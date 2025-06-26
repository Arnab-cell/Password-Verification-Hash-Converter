from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Database setup
def init_db():
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

# Register User
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
                conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                return "User already exists!"
    return render_template('register.html')

# Login User
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None  # Initialize error message variable
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            if user and bcrypt.checkpw(password, user[0]):
                session['username'] = username
                session['password'] = password.decode('utf-8')  # Save original password in session
                session['hashed_password'] = user[0].decode('utf-8')  # Save hashed password
                
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid credentials! Please try again."

    return render_template('login.html', error=error)

# Hash Password Converter (Requires Login)
@app.route('/hash', methods=['GET', 'POST'])
def hash_converter():
    if 'username' not in session:  # Check if the user is logged in
        return redirect(url_for('login'))  # Redirect to login if not logged in

    hashed_password = None  # To store the hashed password

    if request.method == 'POST':
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Hash Converter</title>
    </head>
    <body>
        <h2>Password Hash Converter</h2>
        <form method="post">
            <label for="password">Enter Password:</label>
            <input type="text" name="password" required>
            <button type="submit">Hash</button>
        </form>
        <br>
        {"<strong>Hashed Password:</strong> " + hashed_password if hashed_password else ""}
        <br><br>
        <a href='/dashboard'>Back to Dashboard</a>
    </body>
    </html>
    """


# Dashboard (Protected Route)
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f"""
        <h2>Welcome, {session['username']}!</h2>
        <p><strong>Original Password:</strong> {session['password']}</p>
        <p><strong>Hashed Password:</strong> {session['hashed_password']}</p>
        <br>
        <a href='/logout'>Logout</a>
        """
    return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)