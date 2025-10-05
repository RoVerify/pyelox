def parse_route(path, routes_map):
    path_parts = [p for p in path.split('/') if p]

    for route_path, view_func in routes_map.items():
        route_parts = [p for p in route_path.split('/') if p]

        if len(path_parts) != len(route_parts):
            continue

        url_vars = {}
        match = True
        
        for route_part, path_part in zip(route_parts, path_parts):
            if route_part.startswith('<') and route_part.endswith('>'):
                var_name = route_part[1:-1]
                url_vars[var_name] = path_part
            elif route_part != path_part:
                match = False
                break
        
        if match:
            return view_func, url_vars
            
    return None, None