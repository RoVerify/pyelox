import socket
import threading
import time
import sys
import datetime
import os
from .spacel_gui import SpacelGUI
from .env import get_env

class SpaceLServer:
    def __init__(self, app, host, port):
        self.app = app
        self.host = host
        self.port = port
        self.admin_port = int(get_env('PYELOX_ADMIN_PORT', '9000'))
        self.running = False
        self.server_socket = None
        self.admin_socket = None
        
        self.banned_ips = set()
        self.active_connections = {}
        
        self.session_manager = app.get_tool('session_manager')
        self.admin_gui = SpacelGUI(self, app)

    def ban_ip(self, ip_address):
        self.banned_ips.add(ip_address)
        self.terminate_ip_connections(ip_address)
        return True

    def unban_ip(self, ip_address):
        if ip_address in self.banned_ips:
            self.banned_ips.remove(ip_address)
            return True
        return False
        
    def rename_session(self, session_id, new_name):
        session = self.session_manager.update_session(session_id, '0.0.0.0', new_name)
        return session is not None
        
    def terminate_session(self, session_id):
        session = self.session_manager.sessions.get(session_id)
        if session:
            conn_id = session.get('connection_id')
            if conn_id and conn_id in self.active_connections:
                try:
                    self.active_connections[conn_id].shutdown(socket.SHUT_RDWR)
                    self.active_connections[conn_id].close()
                except Exception:
                    pass
                del self.active_connections[conn_id]
            
            self.session_manager.terminate_session(session_id)
            return True
        return False
        
    def terminate_ip_connections(self, ip_address):
        terminated_count = 0
        connections_to_remove = []
        
        for conn_id, conn in list(self.active_connections.items()):
            if conn.getpeername()[0] == ip_address:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                except Exception:
                    pass
                connections_to_remove.append(conn_id)
                terminated_count += 1
                
        for conn_id in connections_to_remove:
            del self.active_connections[conn_id]
            
        for session_id, session in list(self.session_manager.sessions.items()):
            if session['ip'] == ip_address:
                self.session_manager.terminate_session(session_id)
        
        return terminated_count

    def _client_handler(self, connection, address, conn_id):
        remote_ip = address[0]
        try:
            raw_request = connection.recv(4096)
            if not raw_request:
                return

            self.app.process_request(raw_request, connection, remote_ip)

        except ConnectionResetError:
            pass
        except Exception:
            pass
        finally:
            connection.close()
            if conn_id in self.active_connections:
                del self.active_connections[conn_id]
            
            for session_id, session in list(self.session_manager.sessions.items()):
                if session.get('connection_id') == conn_id:
                    self.session_manager.terminate_session(session_id)
                    break

    def _admin_handler(self, connection, address):
        try:
            raw_request = connection.recv(4096)
            if not raw_request:
                return
            
            remote_addr = address[0]
            response = self.admin_gui.handle_request(raw_request, remote_addr)
            connection.sendall(response)
            
        except Exception:
            pass
        finally:
            connection.close()
            
    def _run_server(self, server_socket, handler_func):
        while self.running:
            try:
                connection, address = server_socket.accept()
                
                if server_socket == self.admin_socket:
                    handler_func(connection, address)
                else:
                    remote_ip = address[0]
                    
                    if remote_ip in self.banned_ips:
                        connection.sendall(b'HTTP/1.1 403 Forbidden\r\nConnection: Close\r\nContent-Length: 0\r\n\r\n')
                        connection.close()
                        continue
                        
                    conn_id = threading.get_ident()
                    self.active_connections[conn_id] = connection
                    
                    client_thread = threading.Thread(
                        target=handler_func, 
                        args=(connection, address, conn_id),
                        name=f"SpaceL-Worker-{address[1]}"
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
            except socket.timeout:
                continue
            except Exception:
                if self.running:
                    continue

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.admin_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.admin_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.admin_socket.bind((self.host, self.admin_port))
            self.admin_socket.listen(1)
            
            self.running = True
            
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{now}] --- Starting PyElox (SpaceL Server) ---")
            print(f"[{now}] SpaceL Is Running in: http://{self.host}:{self.port}")
            print(f"[{now}] SpaceL Admin GUI on: http://{self.host}:{self.admin_port}")
            if self.app.DEBUG:
                print(f"[{now}] DEBUG MODE ACTIVE: Detailed errors and security warnings enabled.")
                
            threading.Thread(target=self._run_server, args=(self.server_socket, self._client_handler), daemon=True).start()
            
            self._run_server(self.admin_socket, self._admin_handler)

        except KeyboardInterrupt:
            print(f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SpaceL Server shutting down gracefully...")
        except Exception as e:
            print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] FATAL: Error during SpaceL server startup: {e}", file=sys.stderr)
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.admin_socket:
            self.admin_socket.close()
            
        for conn in self.active_connections.values():
            try:
                conn.close()
            except Exception:
                pass
        
        os._exit(0)

    def stop_without_exiting(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.admin_socket:
            self.admin_socket.close()
            
        for conn in self.active_connections.values():
            try:
                conn.close()
            except Exception:
                pass
    
    def restart(self):
        self.stop()