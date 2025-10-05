import os

TEMPLATE_DIR = 'templates'

def render_template(template_name, context=None):
    if context is None:
        context = {}
        
    template_path = os.path.join(TEMPLATE_DIR, template_name)
    
    with open(template_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    for key, value in context.items():
        placeholder = '{{ ' + key + ' }}'
        content = content.replace(placeholder, str(value))
        
    return content