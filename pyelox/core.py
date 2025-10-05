from .request import PyEloxRequest
from .router import parse_route
from .spacel import SpaceLServer
from .server import PyEloxServer
from .template import render_template
from .static_handler import serve_static
from .db import PyEloxDB
from .env import load_env, get_env
import traceback
import sys
import datetime

load_env() 

NOT_FOUND_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PyElox - 404 Not Found</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #eef1f5;
            color: #333;
            line-height: 1.6;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        main {
            text-align: center;
            padding: 80px 20px;
            max-width: 600px;
            background-color: white;
            border-radius: 12px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }

        .error-code {
            font-size: 8em;
            color: #CC3333;
            margin-bottom: 0;
            font-weight: 700;
        }
        .error-message {
            font-size: 1.5em;
            color: #555;
            margin-top: 10px;
        }
        .home-link {
            display: inline-block;
            margin-top: 30px;
            padding: 10px 20px;
            background-color: #333;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background-color 0.3s;
        }
        .home-link:hover {
            background-color: #555;
        }
    </style>
</head>
<body>
    
    <main>
        <p class="error-code">404</p>
        <h2 class="error-message">Oops! Resource Not Found.</h2>
        
        <p>We searched everywhere, but the page you were looking for doesn't seem to exist on this server.</p>
        
        <a href="/" class="home-link">Return to Homepage</a>
    </main>
    
</body>
</html>"""

class PyElox:
    def __init__(self):
        self.routes = {}
        self._extensions = {}
        
        self.DEBUG = get_env('PYELOX_DEBUG', 'True') == 'True'
        self.SECRET_KEY = get_env('PYELOX_SECRET_KEY', 'default-unsafe-secret')
        self.DB_NAME = get_env('PYELOX_DB_NAME', 'data/pyelox.db')
        
        self.CORS_HEADERS = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, DELETE, PATCH',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
            'Access-Control-Max-Age': '86400',
            'Access-Control-Allow-Credentials': 'true',
        }
        
        if self.SECRET_KEY == 'default-unsafe-secret':
            print(">>> [SECURITY WARNING]: PYELOX_SECRET_KEY is set to the default unsafe value. Set it in your .env file!", file=sys.stderr)
            
        if get_env('PYELOX_DEBUG') is None:
            print(">>> [CONFIGURATION WARNING]: PYELOX_DEBUG is not set in .env. Defaulting to True.", file=sys.stderr)

        self.db = PyEloxDB(db_name=self.DB_NAME)

    def route(self, path):
        def decorator(func):
            self.routes[path] = func
            return func
        return decorator

    def register_extension(self, name, tool):
        self._extensions[name] = tool
        
    def get_tool(self, name):
        return self._extensions.get(name)
    
    def render(self, template_name, **context):
        return render_template(template_name, context)

    def _handle_cors_preflight(self, connection):
        response_body = b''
        status = '204 NO CONTENT' 
        content_type = 'text/plain'
        
        headers = self.CORS_HEADERS.copy()
        
        status, content_length = self.send_response(connection, status, content_type, response_body, headers=headers)
        return status, content_length


    def send_response(self, connection, status, content_type, response_body, headers=None):
        http_response = []
        http_response.append(f"HTTP/1.1 {status}\r\n")
        
        final_headers = self.CORS_HEADERS.copy()
        if headers:
            final_headers.update(headers)
        
        http_response.append(f"Content-Type: {content_type}\r\n")

        for key, value in final_headers.items():
            http_response.append(f"{key}: {value}\r\n")

        http_response.append(f"Content-Length: {len(response_body)}\r\n")
        http_response.append("\r\n")
        
        final_response_headers = "".join(http_response).encode('utf-8')
        connection.sendall(final_response_headers + response_body)
        
        return status.split()[0], len(response_body)

    def log_request(self, status_code, content_length, remote_addr, method, path):
        now = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        print(f"{now} {remote_addr} - \"{method} {path} HTTP/1.1\" {status_code} {content_length} bytes")

        if '127.0.0.1' in remote_addr or 'localhost' in remote_addr:
            print(f">>> [SECURITY WARNING]: Access from common loopback address ({remote_addr}). Change host for external access.")

    def process_request(self, raw_request, connection, remote_addr):
        request = None
        status = '500 INTERNAL SERVER ERROR'
        content_length = 0
        method = 'UNKNOWN'
        path = 'UNKNOWN'
        
        def parse_cookies(raw_headers):
            cookies = {}
            cookie_header = raw_headers.get('Cookie')
            if cookie_header:
                for cookie in cookie_header.split(';'):
                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookies[name] = value
            return cookies

        try:
            request = PyEloxRequest(raw_request.decode('utf-8'))
            method = request.method
            path = request.path
            
            request.remote_ip = remote_addr
            request.cookies = parse_cookies(request.headers)
            
            if method == 'OPTIONS':
                status_code, content_length = self._handle_cors_preflight(connection)
                self.log_request(status_code, content_length, remote_addr, method, path)
                return
            
            session_manager = self.get_tool('session_manager')
            if session_manager and 'pyelox_session_id' in request.cookies:
                session_id = request.cookies['pyelox_session_id']
                session_manager.update_session_access(session_id, remote_addr)
            
            content_bytes, mime_type = serve_static(request.path)
            
            if content_bytes is not None:
                status, content_length = self.send_response(connection, '200 OK', mime_type, content_bytes)
                return

            view_function, url_vars = parse_route(request.path, self.routes)
            
            if view_function:
                request.url_vars.update(url_vars)
                
                response_content = view_function(request)
                
                if isinstance(response_content, str):
                    response_body = response_content.encode('utf-8')
                    content_type = 'text/html; charset=utf-8'
                    headers = {}
                elif isinstance(response_content, tuple) and len(response_content) == 2:
                    response_body, content_type = response_content
                    headers = {}
                elif isinstance(response_content, tuple) and len(response_content) == 3:
                    response_body, content_type, headers = response_content
                else:
                    response_body = response_content
                    content_type = 'application/octet-stream'
                    headers = {}

                status, content_length = self.send_response(connection, '200 OK', content_type, response_body, headers=headers)
                return
            
            response_body = NOT_FOUND_HTML.encode('utf-8')
            content_type = 'text/html; charset=utf-8'
            status, content_length = self.send_response(connection, '404 NOT FOUND', content_type, response_body)

        except Exception as e:
            if self.DEBUG:
                error_message = traceback.format_exc()
                path_info = request.path if request else "Unknown Path"
                error_html = f"""
                    <html>
                    <head>
                        <title>PyElox ERROR 500</title>
                        <style>
                            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #F8F8F8; color: #333; margin: 0; padding: 0; }}
                            .container {{ max-width: 900px; margin: 50px auto; background: white; border: 1px solid #E0E0E0; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); overflow: hidden; }}
                            .header {{ background-color: #CC3333; color: white; padding: 25px 30px; border-bottom: 5px solid #A32828; }}
                            .header h1 {{ margin: 0; font-size: 2.2em; }}
                            .header p {{ opacity: 0.8; margin-top: 5px; }}
                            .content {{ padding: 30px; }}
                            .path-info {{ background-color: #F0F0F0; padding: 15px; border-radius: 4px; margin-bottom: 20px; font-size: 1.1em; }}
                            .path-info strong {{ color: #CC3333; }}
                            .traceback-container {{ background-color: #2D2D2D; color: #F8F8F8; padding: 20px; border-radius: 4px; overflow-x: auto; }}
                            .traceback-container pre {{ margin: 0; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; line-height: 1.4; }}
                            .error-type {{ color: #FFD700; font-weight: bold; }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h1>SERVER ERROR 500 (DEBUG MODE)</h1>
                                <p>An uncaught exception occurred while processing the request.</p>
                            </div>
                            <div class="content">
                                <div class="path-info">
                                    Error Type: <span class="error-type">{type(e).__name__}</span>
                                    <br>Request Path: <strong>{path_info}</strong>
                                    <br>Raw Request Details: <pre>{raw_request.decode('utf-8').splitlines()[0]}</pre>
                                </div>
                                <h2>Traceback Details:</h2>
                                <div class="traceback-container">
                                    <pre>{error_message}</pre>
                                </div>
                            </div>
                        </div>
                    </body>
                    </html>
                """
                status_code_sent = '500'
                generic_error_body = error_html.encode('utf-8')
                self.send_response(connection, status, 'text/html; charset=utf-8', generic_error_body)
            else:
                generic_error = "<h1>500 Internal Server Error</h1><p>Something went wrong. Contact the administrator.</p>".encode('utf-8')
                status_code_sent = '500'
                self.send_response(connection, status, 'text/html; charset=utf-8', generic_error)

        finally:
            status_code = status.split()[0]
            if content_length > 0:
                self.log_request(status_code, content_length, remote_addr, method, path)
            elif 'status_code_sent' in locals():
                self.log_request(status_code_sent, content_length, remote_addr, method, path)
            else:
                self.log_request(status_code, content_length, remote_addr, method, path)


    def run(self, host='127.0.0.1', port=8000, server_type='SpaceL'):
        if server_type == 'SpaceL':
            server = SpaceLServer(self, host, port)
        else:
            server = PyEloxServer(self, host, port)
            
        server.start()
