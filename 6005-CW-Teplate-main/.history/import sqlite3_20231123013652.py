import sqlite3

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('database.db')

# Create a cursor object using the cursor() method
cursor = conn.cursor()

# Execute an ALTER TABLE command to add a new column
alter_table_command = "INSERT INTO admin VALUES(1,'test@test.com','swordfish');"
cursor.execute(alter_table_command)

# Commit the changes to the database
conn.commit()

# Close the cursor and connection
cursor.close()
conn.close()
