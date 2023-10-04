import sqlite3

db_path="credentials.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# fetching all rows
query = "SELECT * FROM users"
cursor.execute(query)
rows = cursor.fetchall()

# show result
for row in rows:
    print(row)

conn.close()