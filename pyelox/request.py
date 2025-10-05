import urllib.parse
import sys
import traceback

class PyEloxRequest:
    def __init__(self, raw_request):
        self.raw_request = raw_request
        self.headers = {}
        self.method = None
        self.path = None
        self.body = None
        self.form_data = {}
        self.url_vars = {}
        self.query_params = {}
        self.remote_addr = None
        self._parse_request()

    def _parse_request(self):
        try:
            if not self.raw_request:
                return

            lines = self.raw_request.split('\r\n')
            
            if not lines or not lines[0]:
                return

            first_line = lines[0].split()
            if len(first_line) >= 3:
                self.method = first_line[0]
                path_with_query = first_line[1]
                
                if '?' in path_with_query:
                    self.path, query_string = path_with_query.split('?', 1)
                    self.query_params = dict(urllib.parse.parse_qsl(query_string))
                else:
                    self.path = path_with_query
                    self.query_params = {}
            else:
                return

            header_end_index = -1
            try:
                header_end_index = lines.index('') 
            except ValueError:
                header_end_index = len(lines)

            for line in lines[1:header_end_index]:
                if ': ' in line:
                    try:
                        key, value = line.split(': ', 1)
                        self.headers[key.lower()] = value
                    except ValueError:
                        continue
            
            if header_end_index < len(lines):
                self.body = '\r\n'.join(lines[header_end_index + 1:])
                
                if self.method == 'POST' and self.body:
                    content_type = self.headers.get('content-type', '').lower()
                    
                    if 'application/x-www-form-urlencoded' in content_type:
                        self.form_data = dict(urllib.parse.parse_qsl(self.body))
                        
        except Exception as e:
            print(f"CRITICAL ERROR in PyEloxRequest parser: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)


    def get_form(self, key, default=None):
        return self.form_data.get(key, default)

    def get_query(self, key, default=None):
        return self.query_params.get(key, default)
