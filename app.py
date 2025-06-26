from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import bcrypt
import webbrowser
import threading
import os

app = Flask(__name__)
app.secret_key = "ac958917212ca91408d178f0798c8a9dd98ed9c58779365d6ac251bd8f46b8ff"

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

# Redirect root URL to dashboardC
@app.route('/')
def home():
    return redirect(url_for('dashboardC'))

# Register User
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None  # Initialize error message

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
                conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = "User already exists!"

    return render_template('register.html', error=error)


# Login User
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user:
                stored_password = user[0].encode('utf-8') if isinstance(user[0], str) else user[0]
                if bcrypt.checkpw(password, stored_password):
                    session['username'] = username
                    session['original_password'] = request.form['password']  # Store the original password
                    session['hashed_password'] = stored_password.decode('utf-8')
                    return redirect(url_for('dashboardC'))
            return render_template('login.html', error="Invalid credentials! Please try again.")
    return render_template('login.html')

# DashboardC
@app.route('/dashboardC', methods=['GET', 'POST'])
def dashboardC():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template('dashboardC.html',
                           username=session['username'],
                           original_password=session.get('original_password', ''),
                           hashed_password=session.get('hashed_password', ''))

@app.route('/dashboardV', methods=['GET', 'POST'])
def dashboardV():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template('dashboardV.html',
                           username=session['username'],
                           original_password=session.get('original_password', ''),
                           hashed_password=session.get('hashed_password', ''))

# Hash Converter
@app.route('/hash_converter', methods=['POST'])
def hash_converter():
    if 'username' not in session:
        return redirect(url_for('login'))

    text_to_hash = request.form.get('text_to_hash')

    if text_to_hash:
        hashed_version = bcrypt.hashpw(text_to_hash.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        return render_template('dashboardC.html',
                               username=session['username'],
                               original_password=session.get('original_password', ''),
                               hashed_password=session.get('hashed_password', ''),
                               converted_text=text_to_hash,
                               converted_hash=hashed_version)

    return redirect(url_for('dashboardC'))

@app.route('/hash_verifier', methods=['POST'])
def hash_verifier():
    if 'username' not in session:
        return redirect(url_for('login'))

    v_password = request.form.get('v_password')
    v_hash = request.form.get('v_hash')

    if v_password and v_hash:
        try:
            check = bcrypt.checkpw(v_password.encode('utf-8'), v_hash.encode('utf-8'))
        except ValueError:
            check = False
        if check:
            v_message = "Password and hash are a match!"
        else:
            v_message = "Password and hash are not a match!"
        return render_template('dashboardV.html',
                               username=session['username'],
                               original_password=session.get('original_password', ''),
                               hashed_password=session.get('hashed_password', ''),
                               verified_message=v_message,
                               match=check)

    return redirect(url_for('dashboardV'))

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return render_template('logout.html')

def open_browser():
    webbrowser.open_new('http://127.0.0.1:5000')

if __name__ == '__main__':
    init_db()
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        threading.Timer(1.5, open_browser).start()
    app.run(debug=True)