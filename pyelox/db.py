import sqlite3
import threading
import os

class PyEloxDB:
    def __init__(self, db_name='data/pyelox.db'):
        self.db_name = db_name
        self._lock = threading.Lock()
        self._setup_dir()

    def _setup_dir(self):
        base_dir = os.path.dirname(os.path.abspath(self.db_name))
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

    def _get_connection(self):
        return sqlite3.connect(self.db_name)

    def execute_query(self, query, params=None):
        if params is None:
            params = []
        
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute(query, params)
                conn.commit()
                return cursor
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                conn.close()

    def fetch_query(self, query, params=None):
        if params is None:
            params = []
        
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute(query, params)
                results = cursor.fetchall()
                return results
            finally:
                conn.close()

    def select(self, table_name, **filters):
        where_clause = ""
        params = []
        
        if filters:
            where_clause = " WHERE " + " AND ".join(
                [f"{key} = ?" for key in filters.keys()]
            )
            params = list(filters.values())
        
        query = f"SELECT * FROM {table_name}{where_clause}"
        
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute(query, params)
                
                columns = [col[0] for col in cursor.description]
                results = [
                    dict(zip(columns, row)) for row in cursor.fetchall()
                ]
                return results
            finally:
                conn.close()

    def insert(self, table_name, data):
        columns = ', '.join(data.keys())
        placeholders = ', '.join('?' * len(data))
        values = list(data.values())
        
        query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
        self.execute_query(query, values)
        
        return self.select(table_name, username=data.get('username'))[0]

    def update(self, table_name, primary_key_value, updated_fields):
        set_clause = ', '.join([f"{key} = ?" for key in updated_fields.keys()])
        values = list(updated_fields.values())
        
        values.append(primary_key_value)
        
        query = f"UPDATE {table_name} SET {set_clause} WHERE id = ?"
        self.execute_query(query, values)
        
        return self.select(table_name, id=primary_key_value)[0]

    def delete(self, table_name, primary_key_value):
        query = f"DELETE FROM {table_name} WHERE id = ?"
        cursor = self.execute_query(query, [primary_key_value])
        return cursor.rowcount > 0