import sqlite3


def find_user(db: sqlite3.Connection, email: str):
    query = "SELECT id, name FROM users WHERE email = " + email
    return db.execute(query).fetchall()
