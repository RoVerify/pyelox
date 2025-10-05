import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

def get_mime_type(file_path):
    if file_path.endswith('.css'):
        return 'text/css'
    if file_path.endswith('.js'):
        return 'application/javascript'
    if file_path.endswith(('.jpg', '.jpeg')):
        return 'image/jpeg'
    if file_path.endswith('.png'):
        return 'image/png'
    return 'application/octet-stream'

def serve_static(request_path):
    relative_path = request_path.lstrip('/')
    
    if not relative_path or relative_path.strip() == 'static':
        return None, None
    
    if relative_path.startswith('static/'):
        relative_path = relative_path[7:]

    full_path = os.path.join(STATIC_DIR, relative_path)
    full_path = os.path.normpath(full_path)
    
    if not os.path.exists(full_path):
        return None, None

    mime_type = get_mime_type(full_path)
    
    with open(full_path, 'rb') as f:
        content_bytes = f.read()
        
    return content_bytes, mime_type