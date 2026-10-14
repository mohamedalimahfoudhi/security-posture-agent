from app.database.connection import get_connection

try:
    conn = get_connection()
    print("FastAPI database connection works!")
    conn.close()

except Exception as e:
    print("Database error:")
    print(e)