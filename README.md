PyElox: A Minimalist Web Framework
PyElox is a fast, secure, and compact Python web framework built from the socket up, designed for performance, modularity, and explicit control.

🚀 Quick Installation
To use PyElox, you need to install the core dependencies.

pip install python-dotenv Pillow
# Pyelox is not yet on PyPI, but after publication:
# pip install pyelox 

⚙️ Project Setup and Configuration (.env)
PyElox relies on a .env file in your project root for crucial settings, especially security.

Create a file named .env:

```env
PYELOX_DEBUG=True
PYELOX_SECRET_KEY=A-STRONG-AND-UNIQUE-SECRET-KEY-FOR-SESSION-SECURITY
PYELOX_DB_NAME=data/pyelox.db
```

Debugging and Warnings
When PYELOX_DEBUG=True:

Detailed Tracebacks are displayed in the browser in English when an uncaught exception occurs.

Security Warnings are logged to the console (e.g., if PYELOX_SECRET_KEY is set to its default unsafe value, or if access comes from a loopback IP).

💡 Usage Example (APP.py)
This example demonstrates routing, templating, and initializing the database with a secure admin user.

```python
from pyelox import PyElox
from pyelox.security import hash_password
from pyelox.sql import CREATE_USERS_TABLE, SELECT_ADMIN_USER, INSERT_USER

app = PyElox()

def _setup_db():
    try:
        app.db.execute_query(CREATE_USERS_TABLE)
    except Exception:
        pass

    # Check if admin exists using the secure fetch_query method
    if not app.db.fetch_query(SELECT_ADMIN_USER):
        admin_password_hash = hash_password('123')
        
        app.db.execute_query(
            INSERT_USER, 
            ['admin', admin_password_hash, 'Administrator']
        )

@app.route('/')
def index(request):
    return app.render('login.html', message="Please Log In")

@app.route('/dashboard')
def dashboard(request):
    username = request.get_query('user', 'Guest')
    return app.render('dashboard.html', username=username)

if __name__ == '__main__':
    _setup_db()
    app.run(host='127.0.0.1', port=8000, server_type='PyElox')
```

🔑 Core Architecture Details
1. Database Management (pyelox/db.py)
PyElox abstracts SQLite connections, handling concurrent access via threading locks, and ensures connection hygiene to prevent the Cannot operate on a closed database error.

Method

Purpose

Return Type

Usage

execute_query(sql, params)

Write Operations (CREATE, INSERT, UPDATE, DELETE). Commits changes.

sqlite3.Cursor (Do not call fetch methods on it).

app.db.execute_query(INSERT_USER, ['user', hash, 'Role'])

fetch_query(sql, params)

Raw Read Operations (SELECT). Executes query, fetches all results, and closes connection.

list of tuples (raw results).

data = app.db.fetch_query("SELECT id FROM users")

select(table, **filters)

High-Level Read (Recommended). Executes SELECT and converts results into a list of dict (key=column name).

list of dictionaries.

user = app.db.select('users', username='admin')

2. SQL Statements Centralization (pyelox/sql.py)
All raw SQL strings are stored in pyelox/sql.py as constants. This makes the application code cleaner and simplifies adapting to different database backends in the future.

3. Security Utilities (pyelox/security.py)
This module provides basic, essential security operations.

Function

Purpose

hash_password(password)

Securely hashes a plaintext password (currently using SHA-256).

verify_password(stored_hash, provided_password)

Safely compares a provided password against a stored hash using constant-time comparison.

4. Routing and Requests
Method

Purpose

@app.route(path)

Registers a view function for a specific URL path, supporting variable routing (/user/<id>).

request.get_form(key)

Retrieves data from a submitted POST form.

request.get_query(key, default)

Retrieves data from URL query parameters (?key=value).

request.url_vars

Dictionary containing variables extracted from the route path (e.g., the id in /user/<id>).

## SPACEL Server
We recommend SpaceL Server over PyElox Server.

Usage:

```python
from pyelox import PyElox
from pyelox.security import hash_password, verify_password
from pyelox.sql import CREATE_USERS_TABLE, SELECT_ADMIN_USER, INSERT_USER
from pyelox.session_manager import SessionManager

app = PyElox()

app.register_extension('session_manager', SessionManager(app.SECRET_KEY))

def _setup_db():
    try:
        app.db.execute_query(CREATE_USERS_TABLE)
    except Exception:
        pass

    if not app.db.fetch_query(SELECT_ADMIN_USER):
        admin_password_hash = hash_password('123')
        
        app.db.execute_query(
            INSERT_USER, 
            ['admin', admin_password_hash, 'Administrator']
        )

@app.route('/')
def index(request):
    return app.render('login.html', message="")

@app.route('/login')
def login_handler(request):
    if request.method == 'POST':
        username = request.get_form('username')
        password = request.get_form('password')
        
        user_data = app.db.select('users', username=username)
        
        if user_data and verify_password(user_data[0]['password'], password):
            user = user_data[0]
            
            session_manager = app.get_tool('session_manager')
            session_id, session_cookie_value = session_manager.create_session(user['username'])
            
            response_html = f"""
                <html>
                <head><meta http-equiv="refresh" content="0;url=/dashboard?user={user['username']}"></head>
                <body>Redirecting...</body>
                </html>
            """
            
            headers = {
                'Set-Cookie': f'pyelox_session={session_cookie_value}; HttpOnly; Secure; Max-Age=3600; Path=/'
            }
            
            return (response_html.encode('utf-8'), 'text/html; charset=utf-8', headers)
        else:
            return app.render('login.html', message="Incorrect username or password.")

    return app.render('login.html', message="")

@app.route('/register')
def register_handler(request):
    if request.method == 'POST':
        username = request.get_form('username')
        password = request.get_form('password')
        
        if not username or not password:
            return app.render('register.html', message="Username and Password are required.")
            
        existing_users = app.db.select('users', username=username)
        if existing_users:
            return app.render('register.html', message="User already exists.")

        try:
            hashed_password = hash_password(password)
            
            app.db.execute_query(
                INSERT_USER, 
                [username, hashed_password, 'User']
            )
            
            return app.render('login.html', message="Registration successful! Please log in.")
        except Exception:
            return app.render('register.html', message="Error saving user to DB.")

    return app.render('register.html', message="")

@app.route('/dashboard')
def dashboard(request):
    username = request.get_query('user', 'Guest')
    
    session_manager = app.get_tool('session_manager')
    
    session_status = "N/A"
    
    if 'Cookie' in request.headers:
        cookies = request.headers['Cookie']
        if 'pyelox_session=' in cookies:
            session_cookie = cookies.split('pyelox_session=')[1].split(';')[0]
            session_data = session_manager.get_session_data_from_cookie(session_cookie)
            
            if session_data:
                session_manager.update_session(session_data['id'], request.remote_addr)
                session_status = f"Session Active for: {session_data['user']} (ID: {session_data['id'][:8]})"
                
    return app.render('dashboard.html', 
                      username=username,
                      proposta="SpaceL is running securely with built-in Session Management. Check Admin GUI!",
                      status=session_status)

if __name__ == '__main__':
    _setup_db()
    app.run(host='127.0.0.1', port=8000, server_type='SpaceL')
```

## Html Syntax:

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PyElox Dashboard</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <header>
        <h1>PyElox Dashboard</h1>
        <nav><a href="/">Logout</a></nav>
    </header>
    
    <main>
        <h2>Welcome, {{ username }}!</h2>
        <p class="status-message">{{ status }}</p>
        
        <div class="test-proposta">
            <h3>Test Proposal: Persistence</h3>
            <p>{{ proposta }}</p>
            <p>If you shut down the server and run it again, your credentials will still be in the <code class="db-file">data/pyelox.db</code> file, and you will be able to log in again.</p>
        </div>
        
    </main>
    
    <footer>
        <p>Framework under pure Python development.</p>
    </footer>
</body>
</html>

```

## Cors Python Script

```python
from pyelox import PyElox
from pyelox.security import hash_password, verify_password
from pyelox.sql import CREATE_USERS_TABLE, SELECT_ADMIN_USER, INSERT_USER
from pyelox.session_manager import SessionManager
from pyelox.env import get_env
from dotenv import load_dotenv
import json 

load_dotenv(override=True)

app = PyElox()

app.register_extension('session_manager', SessionManager(app.SECRET_KEY))

def _setup_db():
    """Sets up the database and ensures the default admin user exists."""
    try:
        app.db.execute_query(CREATE_USERS_TABLE)
    except Exception:
        pass

    if not app.db.fetch_query(SELECT_ADMIN_USER):
        admin_password_hash = hash_password('123')
        
        app.db.execute_query(
            INSERT_USER, 
            ['admin', admin_password_hash, 'Administrator']
        )

@app.route('/')
def index(request):
    return app.render('login.html', message="")

@app.route('/login')
def login_handler(request):
    if request.method == 'POST':
        username = request.get_form('username')
        password = request.get_form('password')
        
        user_data = app.db.select('users', username=username)
        
        if user_data and verify_password(user_data[0]['password'], password):
            user = user_data[0]
            
            session_manager = app.get_tool('session_manager')
            session_id, session_cookie_value = session_manager.create_session(user['username'])
            
            response_html = f"""
                <html>
                <head><meta http-equiv="refresh" content="0;url=/dashboard?user={user['username']}"></head>
                <body>Redirecting...</body>
                </html>
            """
            
            headers = {
                'Set-Cookie': f'pyelox_session={session_cookie_value}; HttpOnly; Secure; Max-Age=3600; Path=/'
            }
            
            return (response_html.encode('utf-8'), 'text/html; charset=utf-8', headers)
        else:
            return app.render('login.html', message="Incorrect username or password.")

    return app.render('login.html', message="")

@app.route('/register')
def register_handler(request):
    if request.method == 'POST':
        username = request.get_form('username')
        password = request.get_form('password')
        
        if not username or not password:
            return app.render('register.html', message="Username and Password are required.")
            
        existing_users = app.db.select('users', username=username)
        if existing_users:
            return app.render('register.html', message="User already exists.")

        try:
            hashed_password = hash_password(password)
            
            app.db.execute_query(
                INSERT_USER, 
                [username, hashed_password, 'User']
            )
            
            return app.render('login.html', message="Registration successful! Please log in.")
        except Exception:
            return app.render('register.html', message="Error saving user to DB.")

    return app.render('register.html', message="")

@app.route('/dashboard')
def dashboard(request):
    username = request.get_query('user', 'Guest')
    
    session_manager = app.get_tool('session_manager')
    session_status = "N/A"
    
    # Check session
    if 'Cookie' in request.headers:
        cookies = request.headers['Cookie']
        if 'pyelox_session=' in cookies:
            session_cookie = cookies.split('pyelox_session=')[1].split(';')[0]
            session_data = session_manager.get_session_data_from_cookie(session_cookie)
            
            if session_data:
                session_manager.update_session(session_data['id'], request.remote_addr)
                session_status = f"Active Session for: {session_data['user']} (ID: {session_data['id'][:8]})"
                
    return app.render('dashboard.html', 
                      username=username,
                      proposta="SpaceL is running with integrated session management. Check the Admin GUI!",
                      status=session_status)

@app.route('/api/data')
def api_data(request):
    """Simple API endpoint to test CORS functionality."""
    
    # Respond to the browser's Preflight Request
    if request.method == 'OPTIONS':
        return ('', '', {})

    if request.method == 'POST':
        data = {'message': 'Data successfully received and processed via POST with CORS!', 'source': 'PyElox Server'}
    else:
        data = {'message': 'Data successfully retrieved via GET.', 'source': 'PyElox Server'}
    
    response_body = json.dumps(data).encode('utf-8')
    content_type = 'application/json; charset=utf-8'
    
    return (response_body, content_type, {})

@app.route('/cors-test')
def cors_test_page(request):
    """Loads the HTML page with the JavaScript client to perform the CORS test."""
    return app.render('cors_tester.html', target_url="http://127.0.0.1:8000/api/data")


if __name__ == '__main__':
    _setup_db()
    
    host = get_env('PYELOX_HOST', '127.0.0.1')
    
    # --- Safe port handling ---
    raw_port = get_env('PYELOX_PORT', '8000')
    port = 8000 
    
    try:
        if raw_port and raw_port.lower() != 'none':
            port = int(raw_port)
    except ValueError:
        print(f"Warning: Invalid value for PYELOX_PORT ('{raw_port}'). Using default port 8000.")
    # --------------------------
    
    app.run(host=host, port=port, server_type='PyElox')
```

## Cors Html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CORS Test Page</title>
    <style>
        body {
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f7f7f9;
            color: #333;
            min-height: 100vh;
            display: flex;
            justify-content: center;
        }
        .container {
            max-width: 600px;
            width: 100%;
            background-color: #fff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }
        .info-box {
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            line-height: 1.6;
        }
        .info-box code {
            font-weight: bold;
            color: #e74c3c;
        }
        #testButton {
            background-color: #3498db;
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s, transform 0.1s;
            width: 100%;
        }
        #testButton:hover {
            background-color: #2980b9;
        }
        #testButton:active {
            transform: scale(0.99);
        }
        #results {
            margin-top: 25px;
            padding: 15px;
            border-radius: 8px;
            min-height: 100px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .success {
            background-color: #e6ffe6;
            border: 1px solid #00cc00;
            color: #008000;
        }
        .error {
            background-color: #ffe6e6;
            border: 1px solid #cc0000;
            color: #cc0000;
        }
        .loading {
            background-color: #f9f9e6;
            border: 1px solid #cccc00;
            color: #888800;
        }
        .code-block {
            background-color: #f4f4f4;
            padding: 10px;
            border-radius: 4px;
            margin-top: 15px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>CORS Test Page</h1>
        <div class="info-box">
            <p>You are accessing this page on the PyElox server. The test below simulates a request that **forces** the browser to send a CORS verification request (the "Preflight Request," or **OPTIONS**).</p>
            <p>Test URL: <code>{{ target_url }}</code></p>
        </div>
        
        <button id="testButton">Execute POST Test (Forces CORS Preflight)</button>
        
        <h2>Results:</h2>
        <div id="results" class="loading">
            Awaiting test execution...
        </div>
        
        <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS" target="_blank" style="display: block; margin-top: 20px; color: #3498db;">What is CORS?</a>
    </div>

    <script>
        const targetUrl = "{{ target_url }}";
        const resultsDiv = document.getElementById('results');
        const testButton = document.getElementById('testButton');

        async function runCorsTest() {
            resultsDiv.className = 'loading';
            resultsDiv.innerHTML = 'Sending OPTIONS (Preflight) and POST requests...';
            testButton.disabled = true;

            try {
                const response = await fetch(targetUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ action: 'cors_check' })
                });

                if (response.ok) {
                    const data = await response.json();
                    resultsDiv.className = 'success';
                    resultsDiv.innerHTML = `
                        ✅ **SUCCESS!** The CORS request (POST) functioned correctly. Status: ${response.status}.<br>
                        The server successfully processed the Preflight (OPTIONS) request.<br>
                        Response Body (JSON):
                        <div class="code-block">${JSON.stringify(data, null, 2)}</div>
                    `;
                } else {
                    resultsDiv.className = 'error';
                    resultsDiv.innerHTML = `
                        ❌ **CORS/NETWORK ERROR**: The request returned an error status: ${response.status}.
                        This usually means the POST request was blocked or failed after the Preflight.
                        Detailed Status: ${response.statusText}
                    `;
                }
            } catch (error) {
                resultsDiv.className = 'error';
                resultsDiv.innerHTML = `
                    ❌ **CORS/NETWORK ERROR**: The request was blocked by the browser. This means the server failed to respond to the OPTIONS (Preflight) request with the correct CORS headers, or a network error occurred.
                    Detailed Error: ${error.message}
                `;
            } finally {
                testButton.disabled = false;
            }
        }

        testButton.addEventListener('click', runCorsTest);

        document.addEventListener('DOMContentLoaded', () => {
             resultsDiv.innerHTML = 'Click the button to start the test.';
             resultsDiv.className = '';
        });
    </script>
</body>
</html>
```

## Cors SpaceL

```python
from pyelox import PyElox
from pyelox.security import hash_password, verify_password
from pyelox.sql import CREATE_USERS_TABLE, SELECT_ADMIN_USER, INSERT_USER
from pyelox.session_manager import SessionManager
from pyelox.env import get_env
from dotenv import load_dotenv
import json 

load_dotenv(override=True)

app = PyElox()

app.register_extension('session_manager', SessionManager(app.SECRET_KEY))

def _setup_db():
    """Sets up the database and ensures the default admin user exists."""
    try:
        app.db.execute_query(CREATE_USERS_TABLE)
    except Exception:
        pass

    if not app.db.fetch_query(SELECT_ADMIN_USER):
        admin_password_hash = hash_password('123')
        
        app.db.execute_query(
            INSERT_USER, 
            ['admin', admin_password_hash, 'Administrator']
        )

@app.route('/')
def index(request):
    return app.render('login.html', message="")

@app.route('/login')
def login_handler(request):
    if request.method == 'POST':
        username = request.get_form('username')
        password = request.get_form('password')
        
        user_data = app.db.select('users', username=username)
        
        if user_data and verify_password(user_data[0]['password'], password):
            user = user_data[0]
            
            session_manager = app.get_tool('session_manager')
            session_id, session_cookie_value = session_manager.create_session(user['username'])
            
            response_html = f"""
                <html>
                <head><meta http-equiv="refresh" content="0;url=/dashboard?user={user['username']}"></head>
                <body>Redirecting...</body>
                </html>
            """
            
            headers = {
                'Set-Cookie': f'pyelox_session={session_cookie_value}; HttpOnly; Secure; Max-Age=3600; Path=/'
            }
            
            return (response_html.encode('utf-8'), 'text/html; charset=utf-8', headers)
        else:
            return app.render('login.html', message="Incorrect username or password.")

    return app.render('login.html', message="")

@app.route('/register')
def register_handler(request):
    if request.method == 'POST':
        username = request.get_form('username')
        password = request.get_form('password')
        
        if not username or not password:
            return app.render('register.html', message="Username and Password are required.")
            
        existing_users = app.db.select('users', username=username)
        if existing_users:
            return app.render('register.html', message="User already exists.")

        try:
            hashed_password = hash_password(password)
            
            app.db.execute_query(
                INSERT_USER, 
                [username, hashed_password, 'User']
            )
            
            return app.render('login.html', message="Registration successful! Please log in.")
        except Exception:
            return app.render('register.html', message="Error saving user to DB.")

    return app.render('register.html', message="")

@app.route('/dashboard')
def dashboard(request):
    username = request.get_query('user', 'Guest')
    
    session_manager = app.get_tool('session_manager')
    session_status = "N/A"
    
    # Check session
    if 'Cookie' in request.headers:
        cookies = request.headers['Cookie']
        if 'pyelox_session=' in cookies:
            session_cookie = cookies.split('pyelox_session=')[1].split(';')[0]
            session_data = session_manager.get_session_data_from_cookie(session_cookie)
            
            if session_data:
                session_manager.update_session(session_data['id'], request.remote_addr)
                session_status = f"Active Session for: {session_data['user']} (ID: {session_data['id'][:8]})"
                
    return app.render('dashboard.html', 
                      username=username,
                      proposta="SpaceL is running with integrated session management. Check the Admin GUI!",
                      status=session_status)

@app.route('/api/data')
def api_data(request):
    """Simple API endpoint to test CORS functionality."""
    
    # Respond to the browser's Preflight Request
    if request.method == 'OPTIONS':
        return ('', '', {})

    if request.method == 'POST':
        data = {'message': 'Data successfully received and processed via POST with CORS!', 'source': 'PyElox Server'}
    else:
        data = {'message': 'Data successfully retrieved via GET.', 'source': 'PyElox Server'}
    
    response_body = json.dumps(data).encode('utf-8')
    content_type = 'application/json; charset=utf-8'
    
    return (response_body, content_type, {})

@app.route('/cors-test')
def cors_test_page(request):
    """Loads the HTML page with the JavaScript client to perform the CORS test."""
    return app.render('cors_tester.html', target_url="http://127.0.0.1:8000/api/data")


if __name__ == '__main__':
    _setup_db()
    
    host = get_env('PYELOX_HOST', '127.0.0.1')
    
    # --- Safe port handling ---
    raw_port = get_env('PYELOX_PORT', '8000')
    port = 8000 
    
    try:
        if raw_port and raw_port.lower() != 'none':
            port = int(raw_port)
    except ValueError:
        print(f"Warning: Invalid value for PYELOX_PORT ('{raw_port}'). Using default port 8000.")
    # --------------------------
    
    # Changed server_type to 'SpaceL' to use the SpaceLServer class
    app.run(host=host, port=port, server_type='SpaceL')
```