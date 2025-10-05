CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT
)
"""

SELECT_ADMIN_USER = "SELECT * FROM users WHERE username = 'admin'"

INSERT_USER = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"

SELECT_USER_BY_USERNAME = "SELECT * FROM users WHERE username = ?"