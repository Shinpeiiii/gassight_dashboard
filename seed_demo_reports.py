import json
import psycopg2

# Load JSON file
with open("instance/demo_reports.json", "r") as f:
    data = json.load(f)

# Connect to PostgreSQL
conn = psycopg2.connect(
    host="localhost",
    database="your_database",
    user="your_username",
    password="your_password"
)

cur = conn.cursor()

# Insert each JSON object into the table
for item in data:
    cur.execute(
        "INSERT INTO demo_reports (report_data) VALUES (%s)",
        [json.dumps(item)]
    )

conn.commit()
cur.close()
conn.close()

print("Done.")
