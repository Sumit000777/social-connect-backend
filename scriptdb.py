import pymysql
import os
from pymysql.constants import CLIENT
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database Configuration for Aiven MySQL
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT")),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "db": os.getenv("DB_NAME"),
    "charset": "utf8mb4",
    "connect_timeout": 10,
    "read_timeout": 10,
    "write_timeout": 10,
    "cursorclass": pymysql.cursors.DictCursor
}

def add_users_to_lab_group():
    """Add all present users to the 'Lab' group"""
    try:
        # Connect to socialConnect database
        config = DB_CONFIG.copy()
        config["db"] = "socialConnect"
        connection = pymysql.connect(**config)
        
        try:
            with connection.cursor() as cursor:
                # First, check if the Lab group exists
                cursor.execute("SELECT grpname FROM group_ WHERE grpname = 'Lab'")
                group_result = cursor.fetchone()
                
                if not group_result:
                    # Create the Lab group with the first user as admin
                    cursor.execute("SELECT username FROM users LIMIT 1")
                    admin_user = cursor.fetchone()
                    
                    if admin_user:
                        cursor.execute("""
                            INSERT INTO group_ (grpname, admin, bio)
                            VALUES ('Lab', %s, 'Laboratory group for research and collaboration')
                        """, (admin_user['username'],))
                        print("Created Lab group with admin:", admin_user['username'])
                    else:
                        print("Error: No users exist to be admin of the Lab group")
                        return
                
                # Add all users to the Lab group
                cursor.execute("""
                    INSERT IGNORE INTO group_members (grp_name, grpmem)
                    SELECT 'Lab', username FROM users
                """)
                
                affected_rows = cursor.rowcount
                connection.commit()
                print(f"Successfully added {affected_rows} users to the Lab group!")
        
        finally:
            connection.close()
            
    except pymysql.MySQLError as err:
        print(f"Error adding users to Lab group: {err}")
        raise

if __name__ == "__main__":
    add_users_to_lab_group()