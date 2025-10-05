import socket
import threading
import sys

class PyEloxServer:
    def __init__(self, app_core, host, port):
        self.app = app_core
        self.host = host
        self.port = port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        self._socket.bind((self.host, self.port))
        self._socket.listen(5)
        print(f"PyElox Is Running in: http://{self.host}:{self.port}")
        
        try:
            while True:
                client_connection, client_address = self._socket.accept()
                client_handler = threading.Thread(
                    target=self.handle_connection,
                    args=(client_connection, client_address[0])
                )
                client_handler.start()
        except KeyboardInterrupt:
            self._socket.close()
            print("\nPyElox Server Shutdown.")

    def handle_connection(self, client_connection, remote_addr):
        raw_request = b''
        while True:
            try:
                chunk = client_connection.recv(1024)
                if not chunk:
                    break
                raw_request += chunk
                
                if b'\r\n\r\n' in raw_request:
                    break
            except socket.timeout:
                break
            except Exception:
                return

        if not raw_request:
            client_connection.close()
            return

        try:
            self.app.process_request(raw_request, client_connection, remote_addr)
        except Exception as e:
            pass
        finally:
            client_connection.close()
