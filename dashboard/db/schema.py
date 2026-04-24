import sqlite3

def init_db():
    conn = sqlite3.connect('quantumblue-cli/dashboard/db/quantumblue.db')
    cursor = conn.cursor()
    
    # Targets Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            symbol TEXT,
            address TEXT UNIQUE,
            chain TEXT,
            status TEXT DEFAULT 'Scanned'
        )
    ''')
    
    # Vulnerabilities Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            leak_detected BOOLEAN,
            poc_generated BOOLEAN DEFAULT FALSE,
            report_status TEXT DEFAULT 'Open',
            FOREIGN KEY(target_id) REFERENCES targets(id)
        )
    ''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("[+] Database schema initialized.")
