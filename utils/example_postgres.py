import psycopg2

# Connection parameters — adjust if needed
conn = psycopg2.connect(
    host="127.0.0.1",   # or your LAN IP (e.g., 192.168.68.129)
    port=5433,
    dbname="app_dev",
    user="dev_user",
    password="dev_pass"
)

# Use context managers so it auto-commits and closes cleanly
with conn:
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            INSERT INTO users (name, email)
            VALUES
                ('Alice', 'alice@example.com'),
                ('Bob', 'bob@example.com')
            ON CONFLICT DO NOTHING;
        """)
        cur.execute("SELECT * FROM users;")
        rows = cur.fetchall()
        for r in rows:
            print(r)

conn.close()