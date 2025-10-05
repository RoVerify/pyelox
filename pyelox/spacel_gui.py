import json
import time
import traceback
import urllib.parse
import os
from .env import get_env 

class SpacelGUI:
    def __init__(self, spacel_server, app_instance):
        self.server = spacel_server
        self.app = app_instance
        self.routes = {
            '/': self.dashboard_view,
            '/security': self.security_view,
            '/sessions': self.sessions_view,
            '/configurations': self.configurations_view,
            '/action': self.action_handler
        }
        self.config_keys = ['PYELOX_DEBUG', 'PYELOX_DB_NAME', 'PYELOX_PORT', 'PYELOX_ADMIN_PORT']

    def _parse_form_data(self, raw_request):
        try:
            body = raw_request.decode('utf-8').split('\r\n\r\n', 1)[1]
            data = urllib.parse.parse_qs(body)
            return {k: v[0] for k, v in data.items()}
        except Exception:
            return {}

    def _base_html(self, title, body_content, message=None):
        message_html = f'<div style="background-color: #D4EDDA; color: #155724; padding: 10px; border-radius: 5px; margin-bottom: 20px;">{message}</div>' if message else ''
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SpaceL Admin | {title}</title>
            <style>
                body {{ font-family: monospace; background-color: #F0F0F0; margin: 0; padding: 0; }}
                .header {{ background-color: #2D2D2D; color: #FFFFFF; padding: 20px; border-bottom: 3px solid #CC3333; }}
                .header h1 {{ margin: 0; font-size: 1.5em; }}
                .nav a {{ color: #FFD700; margin-right: 15px; text-decoration: none; }}
                .container {{ max-width: 1000px; margin: 20px auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 0.9em; }}
                th {{ background-color: #CC3333; color: white; }}
                .status-ok {{ color: green; font-weight: bold; }}
                .status-warn {{ color: orange; font-weight: bold; }}
                .action-form {{ display: inline-block; margin-right: 5px; }}
                .action-btn {{ background: #333; color: white; border: none; padding: 5px 10px; cursor: pointer; }}
                .ban-btn {{ background: #A32828; }}
                .kick-btn {{ background: #F9A000; }}
                .rename-btn {{ background: #1B8E2A; }}
                .stop-btn {{ background: #000; }}
                .restart-btn {{ background: #007bff; }}
                pre {{ background-color: #2D2D2D; color: #FFD700; padding: 10px; border-radius: 3px; overflow-x: auto; white-space: pre-wrap; }}
                input[type="text"] {{ padding: 5px; border: 1px solid #ccc; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>SpaceL Server Control Panel</h1>
                <div class="nav">
                    <a href="/">Dashboard</a>
                    <a href="/sessions">Active Sessions</a>
                    <a href="/security">Security Status</a>
                    <a href="/configurations">Configurations</a>
                </div>
            </div>
            <div class="container">
                {message_html}
                <h2>{title}</h2>
                {body_content}
            </div>
        </body>
        </html>
        """

    def dashboard_view(self, request):
        status_html = f"""
            <h3>Server Status</h3>
            <p><strong>PyElox Version:</strong> 0.1.1 (Alpha)</p>
            <p><strong>SpaceL Host (Binding):</strong> {get_env('PYELOX_HOST', '0.0.0.0')}:{get_env('PYELOX_PORT', '8000')}</p>
            <p><strong>SpaceL Admin Port:</strong> {get_env('PYELOX_ADMIN_PORT', '9000')}</p>
            <p><strong>Database:</strong> {get_env('PYELOX_DB_NAME', 'data/pyelox.db')}</p>
            <p><strong>Active Connections:</strong> {len(self.server.active_connections)}</p>
            <p><strong>Active Sessions:</strong> {len(self.server.session_manager.sessions)}</p>
            <p><strong>Banned IPs:</strong> {len(self.server.banned_ips)}</p>
            <p><strong>Debug Mode:</strong> {'<span class="status-ok">ON</span>' if self.app.DEBUG else 'OFF'}</p>
            
            <h3>Server Control</h3>
            <form class="action-form" method="POST" action="/action">
                <input type="hidden" name="action" value="restart_server">
                <button type="submit" class="action-btn restart-btn" onclick="return confirm('Are you sure you want to RESTART the server? Connections will be reset.');">RESTART SERVER</button>
            </form>
            <form class="action-form" method="POST" action="/action">
                <input type="hidden" name="action" value="stop_server">
                <button type="submit" class="action-btn stop-btn" onclick="return confirm('Are you sure you want to stop the server?');">STOP SERVER</button>
            </form>
        """
        return status_html

    def security_view(self, request):
        secret_status = self.app.SECRET_KEY != 'default-unsafe-secret'
        
        banned_ips_list = "".join([f"<li>{ip} <form class=\"action-form\" method=\"POST\" action=\"/action\"><input type=\"hidden\" name=\"ip_address\" value=\"{ip}\"><input type=\"hidden\" name=\"action\" value=\"unban_ip\"><button type=\"submit\" class=\"action-btn rename-btn\">Unban</button></form></li>" for ip in self.server.banned_ips])
        
        security_html = f"""
            <h3>Core Security Configuration</h3>
            <p><strong>Secret Key Status:</strong> {'<span class="status-ok">SECURE</span>' if secret_status else '<span class="status-warn">WARNING: Using Default Key!</span>'}</p>
            <p><strong>Session Manager:</strong> {'<span class="status-ok">ACTIVE</span>'}</p>
            
            <h3>Banned IP Addresses ({len(self.server.banned_ips)})</h3>
            <ul>{banned_ips_list or "<li>No IPs are currently banned.</li>"}</ul>

            <h3>Recommendations</h3>
            <ul>
                <li>Ensure `PYELOX_SECRET_KEY` is long, random, and unique.</li>
                <li>Avoid running SpaceL on port 80/443 without a proper proxy (like Nginx).</li>
            </ul>
        """
        return security_html

    def configurations_view(self, request):
        if request.method == 'POST':
            form_data = self._parse_form_data(request.raw_request)
            message = self._process_config_update(form_data)
            return f'HTTP/1.1 303 See Other\r\nLocation: /configurations?message={urllib.parse.quote(message)}\r\n\r\n'
        
        message = request.path.split('message=')[1] if 'message=' in request.path else None
        if message:
            message = urllib.parse.unquote(message)

        return self._base_html("Configurations", self._get_config_form(), message=message), 'text/html; charset=utf-8'

    def _get_config_form(self):
        table_rows = ""
        for key in self.config_keys:
            value = get_env(key)
            if key == 'PYELOX_DEBUG':
                input_field = f"""
                    <select name="{key}">
                        <option value="True" {'selected' if value == 'True' else ''}>True</option>
                        <option value="False" {'selected' if value == 'False' else ''}>False</option>
                    </select>
                """
            else:
                input_field = f'<input type="text" name="{key}" value="{value}" style="width: 250px;">'
            
            table_rows += f"""
                <tr>
                    <td>{key}</td>
                    <td>{input_field}</td>
                </tr>
            """
        
        table_rows += f"""
            <tr>
                <td>PYELOX_SECRET_KEY</td>
                <td><input type="text" value="{'*' * 20 if get_env('PYELOX_SECRET_KEY') != 'default-unsafe-secret' else get_env('PYELOX_SECRET_KEY')}" disabled style="width: 250px;"></td>
            </tr>
        """
        
        config_html = f"""
            <h3>Server Configuration</h3>
            <p>Edit values below. Changes require **server restart** to take full effect on the core application.</p>
            <form method="POST" action="/configurations">
                <table>
                    <tr><th>Setting</th><th>Value</th></tr>
                    {table_rows}
                </table>
                <button type="submit" class="action-btn rename-btn" style="margin-top: 20px;">SAVE TO .env</button>
            </form>
            
            <h3 style="margin-top: 30px;">Restart Server</h3>
            <form class="action-form" method="POST" action="/action">
                <input type="hidden" name="action" value="restart_server">
                <button type="submit" class="action-btn restart-btn" onclick="return confirm('Are you sure you want to RESTART the server?');">RESTART SERVER</button>
            </form>
        """
        return config_html

    def _process_config_update(self, form_data):
        env_path = os.path.join(os.getcwd(), '.env')
        
        env_vars = {}
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            key, value = line.split('=', 1)
                            env_vars[key.strip()] = value.strip().strip('"').strip("'")
                        except ValueError:
                            continue

        changes_made = 0
        for key in self.config_keys:
            if key in form_data:
                new_value = form_data[key]
                if env_vars.get(key) != new_value:
                    env_vars[key] = new_value
                    changes_made += 1

        with open(env_path, 'w') as f:
            for key, value in env_vars.items():
                if ' ' in value or '#' in value or value == '':
                    f.write(f'{key}="{value}"\n')
                else:
                    f.write(f'{key}={value}\n')
        
        if changes_made > 0:
            return f"Success! {changes_made} configuration setting(s) updated in .env. **Restart server** to apply."
        else:
            return "No changes detected or saved."

    def sessions_view(self, request):
        session_list = list(self.server.session_manager.sessions.items())
        
        table_rows = ""
        for session_id, s in session_list:
            session_ip = s.get('ip', 'N/A') 
            last_access = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s['last_access']))
            time_since = int(time.time() - s['last_access'])
            
            action_buttons = f"""
                <form class="action-form" method="POST" action="/action">
                    <input type="hidden" name="session_id" value="{session_id}">
                    <input type="hidden" name="action" value="kick">
                    <button type="submit" class="action-btn kick-btn">Kick</button>
                </form>
                <form class="action-form" method="POST" action="/action">
                    <input type="hidden" name="session_id" value="{session_id}">
                    <input type="hidden" name="action" value="ban">
                    <button type="submit" class="action-btn ban-btn">Ban</button>
                </form>
                <form class="action-form" method="POST" action="/action">
                    <input type="hidden" name="ip_address" value="{session_ip}">
                    <input type="hidden" name="action" value="ban_ip">
                    <button type="submit" class="action-btn ban-btn">Ban IP</button>
                </form>
            """
            rename_form = f"""
                <form class="action-form" method="POST" action="/action">
                    <input type="hidden" name="session_id" value="{session_id}">
                    <input type="hidden" name="action" value="rename">
                    <input type="text" name="new_name" placeholder="New Name" style="width: 80px;">
                    <button type="submit" class="action-btn rename-btn">Rename</button>
                </form>
            """
            
            table_rows += f"""
                <tr>
                    <td>{s.get('user', 'Guest')}</td>
                    <td>{session_ip}</td>
                    <td>{s.get('status', 'Active')}</td>
                    <td>{last_access}</td>
                    <td>{time_since}s ago</td>
                    <td>{action_buttons}{rename_form}</td>
                </tr>
            """
        
        sessions_html = f"""
            <h3>Active User Sessions</h3>
            <p><strong>Total Sessions:</strong> {len(session_list)}</p>
            <table>
                <tr>
                    <th>Username</th>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Last Access Time</th>
                    <th>Time Since</th>
                    <th>Actions</th>
                </tr>
                {table_rows if table_rows else '<tr><td colspan="6">No active sessions found.</td></tr>'}
            </table>
        """
        return sessions_html

    def action_handler(self, request):
        form_data = self._parse_form_data(request.raw_request)
        action = form_data.get('action')
        message = ""
        
        if action == 'kick':
            session_id = form_data.get('session_id')
            success = self.server.terminate_session(session_id)
            message = f"Session {session_id[:8]} kicked successfully." if success else f"Error: Session {session_id[:8]} not found or failed to terminate."
            
        elif action == 'ban':
            session_id = form_data.get('session_id')
            session = self.server.session_manager.sessions.get(session_id)
            if session:
                ip_address = session.get('ip', 'N/A')
                self.server.ban_ip(ip_address)
                message = f"Session {session_id[:8]} terminated and IP {ip_address} banned successfully."
            else:
                message = f"Error: Session {session_id[:8]} not found."

        elif action == 'ban_ip':
            ip_address = form_data.get('ip_address')
            self.server.ban_ip(ip_address)
            message = f"IP address {ip_address} banned and connections terminated."
            
        elif action == 'unban_ip':
            ip_address = form_data.get('ip_address')
            success = self.server.unban_ip(ip_address)
            message = f"IP address {ip_address} unbanned." if success else "Error: IP not found in ban list."

        elif action == 'rename':
            session_id = form_data.get('session_id')
            new_name = form_data.get('new_name')
            success = self.server.rename_session(session_id, new_name)
            message = f"Session {session_id[:8]} renamed to '{new_name}'." if success else f"Error renaming session {session_id[:8]}."
            
        elif action == 'restart_server':
            self.server.restart()
            admin_port = get_env('PYELOX_ADMIN_PORT', '9000') 
            redirect_url = f'http://127.0.0.1:{admin_port}'
            return f"<h3>SpaceL Server Restarting...</h3><p>The server is restarting. Redirecting to <a href='{redirect_url}'>{redirect_url}</a> in 5 seconds...</p><meta http-equiv='refresh' content='5;url={redirect_url}'>", 'text/html; charset=utf-8'

        elif action == 'stop_server':
            self.server.stop()
            return f"<h3>SpaceL Server Stopped</h3><p>The server process has been terminated. You may close this window.</p>", 'text/html; charset=utf-8'

        redirect_content = f"<h3>Action Success</h3><p>{message}</p><p>Redirecting back in 2s...</p><meta http-equiv='refresh' content='2;url=/sessions'>"
        return self._base_html("Action Result", redirect_content, message=message), 'text/html; charset=utf-8'

    def handle_request(self, raw_request, remote_addr):
        try:
            raw_request_str = raw_request.decode('utf-8').split('\r\n')
            if not raw_request_str or not raw_request_str[0]:
                return b'HTTP/1.1 400 Bad Request\r\n\r\n'
            
            method, path_with_query, _ = raw_request_str[0].split()
            
            path = path_with_query.split('?')[0]
            
            view_function = self.routes.get(path)
            
            if view_function:
                temp_request = type('AdminRequest', (object,), {
                    'method': method, 
                    'raw_request': raw_request,
                    'path': path_with_query,
                    'remote_addr': remote_addr
                })
                
                result = view_function(temp_request)
                
                content = result
                content_type = 'text/html; charset=utf-8'
                
                if isinstance(result, tuple):
                    content, content_type = result
                
                if isinstance(content, str) and content.startswith('HTTP/1.1 303'):
                    return content.encode('utf-8')
                
                if not isinstance(content, str):
                    if isinstance(content, bytes):
                        content = content.decode('utf-8')
                    else:
                        content = str(content)

                if path == '/action' or method == 'POST':
                    response_content = content
                else:
                    response_content = self._base_html(path.strip('/').capitalize() or "Dashboard", content)
                
                response_bytes = response_content.encode('utf-8')
                
                return f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {len(response_bytes)}\r\n\r\n'.encode('utf-8') + response_bytes
            
            else:
                response_content = "<h1>404 Not Found</h1>"
                response_bytes = response_content.encode('utf-8')
                return f'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {len(response_bytes)}\r\n\r\n'.encode('utf-8') + response_bytes

        except Exception:
            error_msg = traceback.format_exc()
            response_content = f"<h1>500 Internal Server Error</h1><pre>{error_msg}</pre>"
            response_bytes = response_content.encode('utf-8')
            return f'HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\nContent-Length: {len(response_bytes)}\r\n\r\n'.encode('utf-8') + response_bytes
