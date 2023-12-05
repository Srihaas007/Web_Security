import sqlite3

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('database.db')

# Create a cursor object using the cursor() method
cursor = conn.cursor()

# Execute an ALTER TABLE command to add a new column
create_table_command = "CREATE TABLE seller ( id INTEGER PRIMARY KEY, email TEXT NOT NULL,password TEXT NOT NULL, productID INTEGER NOT NULL);"
cursor.execute(create_table_command)

# Commit the changes to the database
conn.commit()

# Close the cursor and connection
cursor.close()
conn.close()
