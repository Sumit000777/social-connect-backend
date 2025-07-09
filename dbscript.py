import pymysql
import os
from pymysql.constants import CLIENT
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database Configuration for Aiven MySQL
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "s3101@2005"),
    "db": os.getenv("DB_NAME", "social_connect"),
    "charset": "utf8mb4",
    "connect_timeout": 10,
    "read_timeout": 10,
    "write_timeout": 10,
    "cursorclass": pymysql.cursors.DictCursor
}


def reset_database():
    """Reset database by dropping all tables and recreating them with nullable columns"""
    try:
        # Connect to socialConnect database
        config = DB_CONFIG.copy()
        config["db"] = "socialConnect"
        connection = pymysql.connect(**config)
        
        try:
            with connection.cursor() as cursor:
                # Disable foreign key checks to allow dropping tables with foreign key constraints
                cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
                
                # Drop all existing tables in reverse order of dependencies
                tables = [
                    "follow_requests",
                    "group_requests",
                    "group_chat",
                    "chat",
                    "group_members",
                    "group_",
                    "vote",
                    "poll_option",
                    "poll",
                    "follows",
                    "comment_",
                    "like_",
                    "tweet",
                    "users"
                ]
                
                for table in tables:
                    cursor.execute(f"DROP TABLE IF EXISTS {table}")
                    print(f"Dropped table: {table}")
                
                # Re-enable foreign key checks
                cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
                
                # Create tables with nullable fields (except primary keys and essential relations)
                cursor.execute("""
                -- Users table
                CREATE TABLE IF NOT EXISTS users (
                    username VARCHAR(50) PRIMARY KEY NOT NULL,
                    location VARCHAR(100) NULL,
                    bio TEXT NULL,
                    mailid VARCHAR(100) UNIQUE NOT NULL,
                    website VARCHAR(200) NULL,
                    fname VARCHAR(50) NULL,
                    lname VARCHAR(50) NULL,
                    photo LONGTEXT NULL,
                    dateofbirth DATE NULL,
                    joined_from DATE NULL,
                    password VARCHAR(255) NULL
                )
                """)
                
                cursor.execute("""
                -- Tweet table
                CREATE TABLE IF NOT EXISTS tweet (
                    tweetid INT PRIMARY KEY NOT NULL,
                    content_ TEXT NULL,
                    photo LONGTEXT NULL,
                    time_ TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    author VARCHAR(50) NOT NULL,
                    FOREIGN KEY (author) REFERENCES users(username) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Like table
                CREATE TABLE IF NOT EXISTS like_ (
                    username VARCHAR(50) NOT NULL,
                    tweetid INT NOT NULL,
                    PRIMARY KEY (username, tweetid),
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY (tweetid) REFERENCES tweet(tweetid) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Comment table
                CREATE TABLE IF NOT EXISTS comment_ (
                    _id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
                    time_ TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    tweetid INT NOT NULL,
                    username VARCHAR(50) NOT NULL,
                    content_ TEXT NULL,
                    FOREIGN KEY (tweetid) REFERENCES tweet(tweetid) ON DELETE CASCADE,
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Follow table
                CREATE TABLE IF NOT EXISTS follows (
                    follower VARCHAR(50) NOT NULL,
                    follows VARCHAR(50) NOT NULL,
                    PRIMARY KEY (follower, follows),
                    FOREIGN KEY (follower) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY (follows) REFERENCES users(username) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Poll table
                CREATE TABLE IF NOT EXISTS poll (
                    id_ INT PRIMARY KEY NOT NULL,
                    content_ TEXT NULL,
                    poll_by VARCHAR(50) NOT NULL,
                    time_ TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (poll_by) REFERENCES users(username) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Poll option table
                CREATE TABLE IF NOT EXISTS poll_option (
                    poll_id INT NOT NULL,
                    option_ VARCHAR(200) NOT NULL,
                    PRIMARY KEY (poll_id, option_),
                    FOREIGN KEY (poll_id) REFERENCES poll(id_) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Vote table
                CREATE TABLE IF NOT EXISTS vote (
                    username VARCHAR(50) NOT NULL,
                    poll_id INT NOT NULL,
                    poll_option_ VARCHAR(200) NULL, 
                    PRIMARY KEY (username, poll_id),
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY (poll_id) REFERENCES poll(id_) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Group table
                CREATE TABLE IF NOT EXISTS group_ (
                    grpname VARCHAR(50) PRIMARY KEY NOT NULL,
                    admin VARCHAR(50) NOT NULL,
                    photo LONGTEXT NULL,
                    bio TEXT NULL,
                    FOREIGN KEY (admin) REFERENCES users(username) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Group members table
                CREATE TABLE IF NOT EXISTS group_members (
                    grp_name VARCHAR(50) NOT NULL,
                    grpmem VARCHAR(50) NOT NULL,
                    PRIMARY KEY (grp_name, grpmem),
                    FOREIGN KEY (grp_name) REFERENCES group_(grpname) ON DELETE CASCADE,
                    FOREIGN KEY (grpmem) REFERENCES users(username) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Chat table
                CREATE TABLE IF NOT EXISTS chat (
                    id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
                    sender VARCHAR(50) NOT NULL,
                    receiver VARCHAR(50) NOT NULL,
                    msg TEXT NULL,
                    time_ TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY (receiver) REFERENCES users(username) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Group chat table
                CREATE TABLE IF NOT EXISTS group_chat (
                    id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
                    grp_name VARCHAR(50) NOT NULL,
                    sender VARCHAR(50) NOT NULL,
                    message TEXT NULL,
                    time_ TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (grp_name) REFERENCES group_(grpname) ON DELETE CASCADE,
                    FOREIGN KEY (sender) REFERENCES users(username) ON DELETE CASCADE
                )
                """)
                
                cursor.execute("""
                -- Group membership requests table
                CREATE TABLE IF NOT EXISTS group_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
                    grp_name VARCHAR(50) NOT NULL,
                    username VARCHAR(50) NOT NULL,
                    request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                    FOREIGN KEY (grp_name) REFERENCES group_(grpname) ON DELETE CASCADE,
                    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
                    UNIQUE KEY (grp_name, username)
                )
                """)
                
                cursor.execute("""
                -- Follow requests table
                CREATE TABLE IF NOT EXISTS follow_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
                    requester VARCHAR(50) NOT NULL,
                    target VARCHAR(50) NOT NULL,
                    request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                    FOREIGN KEY (requester) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY (target) REFERENCES users(username) ON DELETE CASCADE,
                    UNIQUE KEY (requester, target)
                )
                """)
            
            connection.commit()
            print("Database tables dropped and recreated successfully!")
            
        finally:
            connection.close()
            
    except pymysql.MySQLError as err:
        print(f"Database reset error: {err}")
        raise

if __name__ == "__main__":
    reset_database()