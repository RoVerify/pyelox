import uuid
import time
import base64
import json

class SessionManager:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.sessions = {}

    def _hash_data(self, data):
        key = self.secret_key[:len(data)]
        if len(key) < len(data):
            key = (key * (len(data) // len(key) + 1))[:len(data)]
            
        encrypted_bytes = bytes([a ^ b for a, b in zip(data.encode('utf-8'), key.encode('utf-8'))])
        return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')

    def _unhash_data(self, hashed_data):
        try:
            encrypted_bytes = base64.urlsafe_b64decode(hashed_data.encode('utf-8'))
            key = self.secret_key[:len(encrypted_bytes)]
            if len(key) < len(encrypted_bytes):
                key = (key * (len(encrypted_bytes) // len(key) + 1))[:len(encrypted_bytes)]
            
            decrypted_bytes = bytes([a ^ b for a, b in zip(encrypted_bytes, key.encode('utf-8'))])
            return decrypted_bytes.decode('utf-8')
        except:
            return None

    def create_session(self, username, ip_address='0.0.0.0'): 
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'user': username,
            'ip': ip_address,
            'created': time.time(),
            'last_access': time.time(),
            'status': 'ACTIVE',
            'connection_id': None 
        }
        
        session_data = json.dumps({'id': session_id, 'user': username})
        return session_id, self._hash_data(session_data)

    def update_session(self, session_id, ip_address, new_username=None):
        if session_id in self.sessions:
            self.sessions[session_id]['last_access'] = time.time()
            self.sessions[session_id]['ip'] = ip_address
            if new_username:
                self.sessions[session_id]['user'] = new_username
            return self.sessions[session_id]
        return None
        
    def update_session_access(self, session_id, ip_address):
        if session_id in self.sessions:
            self.sessions[session_id]['last_access'] = time.time()
            self.sessions[session_id]['ip'] = ip_address
            return True
        return False

    def terminate_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False

    def get_session_data_from_cookie(self, cookie_value):
        data = self._unhash_data(cookie_value)
        if data:
            return json.loads(data)
        return None