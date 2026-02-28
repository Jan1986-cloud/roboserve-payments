import os
import pymysql

try:
    conn = pymysql.connect(
        host=os.getenv("MARIADB_PRIVATE_HOST"),
        user=os.getenv("MARIADB_USER"),
        password=os.getenv("MARIADB_PASSWORD"),
        database=os.getenv("MARIADB_DATABASE"),
        port=int(os.getenv("MARIADB_PRIVATE_PORT")),
        cursorclass=pymysql.cursors.DictCursor
    )
    print("Connection successful!")
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users")
        result = cursor.fetchall()
        print("Users table content:")
        for row in result:
            print(row)
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    if 'conn' in locals() and conn.open:
        conn.close()
        print("Connection closed.")
