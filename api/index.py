from flask import Flask, render_template, request, redirect, make_response, render_template_string, url_for
import os
from urllib.parse import unquote
import base64

app = Flask(__name__, template_folder='../templates', static_folder='../static')

class Confidential:
    def __init__(self, secret):
        self.secret = secret
    def __repr__(self):
        return "<Confidential Value>"
    def __str__(self):
        return self.secret

# --- CONFIGURATION & FLAGS ---
FLAG_COMMENT = os.environ.get('FLAG_COMMENT', 'axios{default_comment_flag}')
FLAG_ROBOTS = os.environ.get('FLAG_ROBOTS', 'axios{default_robots_flag}')
FLAG_BAC = os.environ.get('FLAG_BAC', 'axios{default_bac_flag}')
FLAG_SSTI = os.environ.get('FLAG_SSTI', 'axios{default_ssti_flag}')
FLAG_IDOR = os.environ.get('FLAG_IDOR', 'axios{default_idor_flag}')
FLAG_PYJAIL = os.environ.get('FLAG_PYJAIL', 'axios{default_pyjail_flag}')

app.config['SecretFlag'] = Confidential(FLAG_SSTI)
SUPER_SECRET_FLAG_6 = Confidential(FLAG_PYJAIL)

# --- MOCK DATABASE ---
USERS = {
    "admin": {"password": "X9#mP2!vL_impossible_guess", "role": "admin", "id": 0},
    "alice": {"password": "alice123", "role": "user", "id": 1},
    "bob": {"password": "bob123", "role": "user", "id": 2},
    "charlie": {"password": "charlie123", "role": "user", "id": 3},
    "dave": {"password": "dave123", "role": "user", "id": 4},
}

TODOS = {
    0: ["Review Q3 Financials", "Fire improper employees", "Update credentials", f"FLAG: {FLAG_IDOR}"],
    1: ["Buy milk", "Walk the dog", "Learn React"],
    2: ["Finish CTF challenge", "Sleep 8 hours", "Debug production"],
    3: ["Gym", "Tan", "Laundry"],
    4: ["Write poetry", "Fix the printer"]
}

# Limits to prevent crashes
MAX_USERS = 50
MAX_TODOS_PER_USER = 20

# --- ROUTES ---

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and USERS[username]['password'] == password:
            resp = make_response(redirect('/dashboard'))
            raw_role = USERS[username]['role']
            encoded_role = base64.b64encode(raw_role.encode()).decode()
            resp.set_cookie('user_id', str(USERS[username]['id']))
            resp.set_cookie('role', encoded_role)
            resp.set_cookie('username', username)
            return resp
        else:
            return render_template('login.html', error="Invalid credentials", hidden_flag=FLAG_COMMENT)
    return render_template('login.html', hidden_flag=FLAG_COMMENT)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if len(USERS) >= MAX_USERS:
            return render_template('signup.html', error="Registration closed: Max users reached.")
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS:
            return render_template('signup.html', error="Username already exists")
        new_id = len(USERS) + 10
        USERS[username] = {"password": password, "role": "user", "id": new_id}
        TODOS[new_id] = ["Welcome to TaskFlow!"]
        return redirect('/login')
    return render_template('signup.html')

@app.route('/logout')
def logout():
    resp = make_response(redirect('/login'))
    resp.set_cookie('user_id', '', expires=0)
    resp.set_cookie('role', '', expires=0)
    resp.set_cookie('username', '', expires=0)
    return resp

@app.route('/dashboard')
def dashboard():
    user_id_cookie = request.cookies.get('user_id')
    if not user_id_cookie:
        return redirect('/login')
    
    target_id = request.args.get('uid')
    if not target_id:
        return redirect(f'/dashboard?uid={user_id_cookie}')
    
    current_list = []
    viewing_as = "Unknown"
    
    try:
        t_id_int = int(target_id)
        current_list = TODOS.get(t_id_int, [])
        if str(t_id_int) == user_id_cookie:
            viewing_as = request.cookies.get('username')
        else:
            viewing_as = f"User ID {t_id_int}"
    except ValueError:
        current_list = []
        viewing_as = "Invalid ID"

    return render_template('dashboard.html', todos=current_list, user=viewing_as, my_id=user_id_cookie)

@app.route('/add_todo', methods=['POST'])
def add_todo():
    user_id = request.cookies.get('user_id')
    task_text = request.form.get('task')
    if user_id and task_text:
        try:
            uid = int(user_id)
            if uid not in TODOS: TODOS[uid] = []
            if len(TODOS[uid]) < MAX_TODOS_PER_USER:
                TODOS[uid].append(task_text)
        except ValueError:
            pass
    return redirect(f'/dashboard?uid={user_id}')

@app.route('/delete_todo/<int:index>')
def delete_todo(index):
    user_id = request.cookies.get('user_id')
    if user_id:
        try:
            uid = int(user_id)
            # Prevent users from deleting Admin's flag
            if uid == 0: 
                return redirect(f'/dashboard?uid={user_id}')
            
            if uid in TODOS and 0 <= index < len(TODOS[uid]):
                TODOS[uid].pop(index)
        except ValueError:
            pass
    return redirect(f'/dashboard?uid={user_id}')

@app.route('/admin')
def admin():
    encoded_role = request.cookies.get('role')
    role = ""
    if encoded_role:
        try:
            role = base64.b64decode(encoded_role).decode()
        except Exception:
            role = "invalid"
    if role == 'admin':
        return render_template('admin.html', flag=FLAG_BAC)
    else:
        return render_template('admin.html', error="Access Denied. Admins only."), 403

@app.route('/robots.txt')
def robots():
    response = make_response(f"User-agent: *\nDisallow: /backup-flag\n\n# Flag Part 2: {FLAG_ROBOTS}")
    response.headers["Content-Type"] = "text/plain"
    return response

@app.route('/backup-flag')
def backup_flag():
    return "You found the path! The flag was in robots.txt."

@app.errorhandler(404)
def page_not_found(e):
    decoded_path = unquote(request.path)
    
    # WAF: Prevent DoS and RCE
    if len(decoded_path) > 100:
        return "Error: URL too long.", 400
    dangerous_chars = ['_', '[', ']', 'os', 'import']
    for char in dangerous_chars:
        if char in decoded_path:
            return "WAF Blocked: Malicious characters detected in URL.", 400

    template = f'''
    <div style="text-align:center; padding: 50px; font-family: sans-serif;">
        <h1>404 - Page Not Found</h1>
        <p>The page <b>{decoded_path}</b> does not exist on this server.</p>
        <a href="/dashboard">Go Home</a>
    </div>
    '''
    return render_template_string(template), 404


def is_safe_expression(expr):
    blacklist = [
        'import', 'os', 'sys', 'open', 'read', 'write', 
        'subprocess', 'popen', 'cat', 'flag', 'config', 
        'builtins', '__', 'getattr', 'setattr', 'delattr', 
        'exit', 'quit', 'input', 'help',
        'admin', 'dashboard', 'login', 'register',
        'pow', 'sum', 'range', 'list' 
    ]
    expr_lower = expr.lower()
    for word in blacklist:
        if word in expr_lower:
            return False, f"Malicious input detected: '{word}' is blocked."
    if len(expr) > 50:
        return False, "Expression too long."
    return True, ""

@app.route('/calculator', methods=['GET', 'POST'])
def calculator():
    result = None
    error = None
    if request.method == 'POST':
        expression = request.form.get('expression', '')
        is_safe, message = is_safe_expression(expression)
        if not is_safe:
            error = message
        else:
            try:
                # Sandbox: User only sees what we put here
                hidden_flag = Confidential(FLAG_PYJAIL)
                sandbox_globals = {
                    '__builtins__': __builtins__,
                    'SUPER_SECRET_FLAG_6': hidden_flag,
                }
                result = eval(expression, sandbox_globals)
            except Exception as e:
                error = f"Calculation Error: {str(e)}"
    return render_template('calculator.html', result=result, error=error)

if __name__ == '__main__':
    app.run(debug=True)