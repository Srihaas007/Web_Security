import sqlite3

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('database.db')

# Create a cursor object using the cursor() method
cursor = conn.cursor()

# Close the connection when done
conn.close()
