from fastapi import FastAPI, Form, File, UploadFile, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
import pymysql
import base64
from datetime import datetime, timedelta,timezone
import codecs
import uvicorn
import os
from dotenv import load_dotenv
import jwt as pyjwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Load environment variables from .env file
load_dotenv()

app = FastAPI(title="SocialConnect API")

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "temp_3x@mpl3_s3cr3t_k3y_2025")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class UserAuth(BaseModel):
    username: str
    password: str

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Configuration for Aiven MySQL (using env variables)
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

# Helper Functions
def get_db_connection():
    """Create and return a PyMySQL database connection"""
    try:
        conn = pymysql.connect(**DB_CONFIG)
        return conn
    except pymysql.MySQLError as err:
        print(f"MySQL Connection Error: {err}")
        raise HTTPException(status_code=500, detail=f"Database connection error: {err}")

def execute_query(query, params=None, fetch=True, commit=False):
    """Execute a SQL query and return results if needed"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            if fetch:
                result = cursor.fetchall()
            else:
                result = None
                
            if commit:
                conn.commit()
                
            return result
    except pymysql.MySQLError as err:
        print(f"Query Error: {err}")
        print(f"Query: {query}")
        if params:
            print(f"Params: {params}")
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database query error: {err}")
    finally:
        conn.close()

def hex_to_base64(hex_data):
    """Convert hex string to base64"""
    if not hex_data:
        return ""
    b64 = codecs.encode(codecs.decode(hex_data, 'hex'), 'base64').decode().strip()
    return b64

def binary_from_photo_object(photo_obj):
    """Convert photo file object to base64 string for direct use in data URLs"""
    if not photo_obj:
        return ""
    content = photo_obj.file.read()
    return base64.b64encode(content).decode("utf-8")

# Password hashing functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# JWT functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = pyjwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except pyjwt.PyJWTError:
        raise credentials_exception

# Root Endpoint
@app.get("/")
def home():
    return {
        "message": "SocialConnect API",
        "available_endpoints": [
            "GET /feed/{username}",
            "GET /user/{username}",
            "GET /tweet/{tweet_id}",
            "POST /new_user",
            "POST /new_tweet",
            "POST /new_comment",
            "POST /new_follow",
            "POST /new_like",
            "POST /token",
            "GET /me",
            "And many more..."
        ]
    }

# Authentication Endpoints
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Check if user exists
    user_query = "SELECT * FROM users WHERE username = %s"
    user_data = execute_query(user_query, (form_data.username,))
    
    if not user_data:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = user_data[0]
    
    # Verify password
    if not verify_password(form_data.password, user['password']):
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['username']}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me")
def get_current_user_info(current_user: str = Depends(get_current_user)):
    user_query = "SELECT * FROM users WHERE username = %s"
    user_data = execute_query(user_query, (current_user,))
    
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Remove password from response
    if user_data[0].get('password'):
        del user_data[0]['password']
    
    return user_data[0]

# User Endpoints
@app.get("/user/{username}")
def get_user(username: str, current_user: str = Depends(get_current_user)):
    # Get user profile
    user_query = "SELECT * FROM users WHERE username = %s"
    user_data = execute_query(user_query, (username,))
    
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Remove password from response
    if user_data[0].get('password'):
        del user_data[0]['password']
    
    # Get user tweets
    tweets_query = """
    SELECT users.username, CONCAT(users.fname, ' ', users.lname) AS author, 
           users.photo AS userphoto, tweet.tweetid, tweet.content_, tweet.photo
    FROM tweet INNER JOIN users ON
    tweet.author = users.username AND users.username = %s
    ORDER BY tweet.time_ DESC
    """
    tweets_data = execute_query(tweets_query, (username,))
    
    # Get followers
    followers_query = """
    SELECT users.username, users.photo 
    FROM follows INNER JOIN users ON follows.follower = users.username 
    WHERE follows.follows = %s
    """
    followers_data = execute_query(followers_query, (username,))
    
    return {
        "profile": user_data[0] if user_data else None,
        "tweets": tweets_data,
        "followers": followers_data
    }

@app.post("/new_user")
async def create_user(
    username: str = Form(...),
    password: str = Form(...),  # Add password field
    location: str = Form(...),
    bio: str = Form(...),
    mailid: str = Form(...),
    website: str = Form(...),
    firstname: str = Form(...),
    lastname: str = Form(...),
    dateofbirth: str = Form(...),
    photo: Optional[UploadFile] = File(None)
):
    # Process photo if provided
    photo_base64 = ""
    if photo:
        content = await photo.read()
        photo_base64 = base64.b64encode(content).decode("utf-8")
    
    joined_from = datetime.today().strftime('%Y-%m-%d')
    
    # Check if user already exists
    check_query = "SELECT username FROM users WHERE username = %s"
    existing_user = execute_query(check_query, (username,))
    
    if existing_user:
        raise HTTPException(status_code=409, detail="Username already exists")
    
    # Hash the password
    hashed_password = get_password_hash(password)
    
    # Insert new user with hashed password
    insert_query = """
    INSERT INTO users 
    (username, password, location, bio, mailid, website, fname, lname, photo, dateofbirth, joined_from) 
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    params = (username, hashed_password, location, bio, mailid, website, firstname, lastname, 
              photo_base64, dateofbirth, joined_from)
    
    execute_query(insert_query, params, fetch=False, commit=True)
    
    return {"status": "success", "message": "User created successfully"}


@app.get("/feed/{username}")
def get_feed(username: str):
    # Get tweets from users that the current user follows (and user's own tweets)
    query = """
    SELECT users.username, CONCAT(users.fname, ' ', users.lname) AS author, 
           users.photo AS userphoto, tweet.tweetid, tweet.content_, tweet.photo, tweet.time_
    FROM tweet INNER JOIN users ON
    tweet.author = users.username  
    WHERE (users.username IN 
        (SELECT follows FROM follows WHERE follower = %s) 
        OR users.username = %s)
    ORDER BY tweet.time_ DESC
    """
    
    tweets = execute_query(query, (username, username))
    
    # For each tweet, get likes information
    for tweet in tweets:
        tweet_id = tweet["tweetid"]
        
        # Get users who liked this tweet
        likes_query = """
        SELECT users.username, users.photo AS userphoto
        FROM users INNER JOIN like_ ON
        users.username = like_.username AND like_.tweetid = %s
        """
        likes = execute_query(likes_query, (tweet_id,))
        
        # Add likes information to the tweet
        tweet["likes"] = likes
        tweet["like_count"] = len(likes)
        tweet["liked_by_user"] = any(like["username"] == username for like in likes)
    
    return {"data":tweets}

# Tweet Endpoints
@app.get("/tweet/{tweet_id}")
def get_tweet(tweet_id: int, current_user: str = Depends(get_current_user)):
    query = """
    SELECT users.username, CONCAT(users.fname, ' ', users.lname) AS author, 
           users.photo AS userphoto, tweet.tweetid, tweet.content_, tweet.photo, tweet.time_
    FROM tweet INNER JOIN users ON
    tweet.author = users.username AND tweet.tweetid = %s
    """
    
    data = execute_query(query, (tweet_id,))
    
    if not data:
        raise HTTPException(status_code=404, detail="Tweet not found")
        
    return data

@app.get("/full_tweet/{tweet_id}")
def get_full_tweet(tweet_id: int, current_user: str = Depends(get_current_user)):
    # Get tweet data
    tweet_query = """
    SELECT users.username, CONCAT(users.fname, ' ', users.lname) AS author, 
           users.photo AS userphoto, tweet.tweetid, tweet.content_, tweet.photo, tweet.time_
    FROM tweet INNER JOIN users ON
    tweet.author = users.username AND tweet.tweetid = %s
    """
    tweet_data = execute_query(tweet_query, (tweet_id,))
    
    if not tweet_data:
        raise HTTPException(status_code=404, detail="Tweet not found")
    
    # Get likes
    likes_query = """
    SELECT users.username, users.photo AS userphoto
    FROM users INNER JOIN like_ ON
    users.username = like_.username AND like_.tweetid = %s
    """
    likes_data = execute_query(likes_query, (tweet_id,))
    
    # Get comments
    comments_query = """
    SELECT comment_.time_, comment_._id, comment_.tweetid, comment_.content_, 
           users.username, CONCAT(users.fname, ' ', users.lname) AS author, users.photo AS userphoto 
    FROM comment_ INNER JOIN users ON
    comment_.username = users.username AND comment_.tweetid = %s
    ORDER BY comment_.time_
    """
    comments_data = execute_query(comments_query, (tweet_id,))
    
    liked_users = [user["username"] for user in likes_data]
    
    return {
        "tweet": tweet_data,
        "likes": likes_data,
        "comments": comments_data,
        "liked_users": liked_users
    }

@app.post("/new_tweet")
async def create_tweet(
    username: str = Form(...),
    content: str = Form(...),
    photo: Optional[UploadFile] = File(None),
    group_name: Optional[str] = Form(None),
    current_user: str = Depends(get_current_user)
):
    # Validate that the username matches the authenticated user
    if username != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to post as another user")
    
    try:
        # Process photo if provided
        photo_data = None
        if photo:
            contents = await photo.read()
            photo_data = base64.b64encode(contents).decode('utf-8')
        
        # Generate a unique tweet ID
        id_query = "SELECT COALESCE(MAX(tweetid), 0) + 1 AS next_id FROM tweet"
        next_id_data = execute_query(id_query)
        new_tweet_id = next_id_data[0]["next_id"] if next_id_data else 1
        
        # Insert tweet
        query = """
        INSERT INTO tweet (tweetid, content_, photo, author, group_name)
        VALUES (%s, %s, %s, %s, %s)
        """
        execute_query(query, (new_tweet_id, content, photo_data, username, group_name), fetch=False, commit=True)
        
        return {"status": "success", "tweet_id": new_tweet_id}
    except Exception as e:
        print(f"Error creating tweet: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/delete_tweet/{tweet_id}")
def delete_tweet(tweet_id: int, current_user: str = Depends(get_current_user)):
    # Check if tweet exists and is owned by the current user
    check_query = "SELECT tweetid, author FROM tweet WHERE tweetid = %s"
    tweet = execute_query(check_query, (tweet_id,))
    
    if not tweet:
        raise HTTPException(status_code=404, detail="Tweet not found")
    
    if tweet[0]["author"] != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to delete this tweet")
    
    # Delete tweet
    delete_query = "DELETE FROM tweet WHERE tweetid = %s"
    execute_query(delete_query, (tweet_id,), fetch=False, commit=True)
    
    return {"status": "success", "message": "Tweet deleted"}

@app.get("/all_followers/{username}")
def get_all_followers(username: str, current_user: str = Depends(get_current_user)):
    """Get all followers for a specific user"""
    query = """
    SELECT users.username, users.photo, CONCAT(users.fname, ' ', users.lname) AS full_name 
    FROM follows 
    INNER JOIN users ON follows.follower = users.username 
    WHERE follows.follows = %s
    ORDER BY users.username
    """
    
    data = execute_query(query, (username,))
    return data

# Like Endpoints
@app.post("/new_like")
async def like_tweet(
    tweet_id: int = Form(...),
    user_id: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    # Ensure user is liking as themselves
    if user_id != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to like as another user")
    
    # Check if already liked
    check_query = "SELECT * FROM like_ WHERE tweetid = %s AND username = %s"
    existing_like = execute_query(check_query, (tweet_id, user_id))
    
    if existing_like:
        return {"status": "info", "message": "Already liked"}
    
    # Insert like
    insert_query = "INSERT INTO like_ (username, tweetid) VALUES (%s, %s)"
    execute_query(insert_query, (user_id, tweet_id), fetch=False, commit=True)
    
    return {"status": "success", "message": "Tweet liked"}

@app.post("/new_unlike")
async def unlike_tweet(
    tweet_id: int = Form(...),
    user_id: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    # Ensure user is unliking as themselves
    if user_id != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to unlike as another user")
    
    # Delete like
    delete_query = "DELETE FROM like_ WHERE tweetid = %s AND username = %s"
    execute_query(delete_query, (tweet_id, user_id), fetch=False, commit=True)
    
    return {"status": "success", "message": "Tweet unliked"}

@app.get("/likes_by_tweeter_id/{tweet_id}")
def get_likes(tweet_id: int, current_user: str = Depends(get_current_user)):
    query = """
    SELECT users.username, users.photo AS userphoto
    FROM users INNER JOIN like_ ON
    users.username = like_.username AND like_.tweetid = %s
    """
    
    data = execute_query(query, (tweet_id,))
    return data

# Comment Endpoints
@app.post("/new_comment")
async def create_comment(
    tweet_id: int = Form(...),
    username: str = Form(...),
    content: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    # Ensure user is commenting as themselves
    if username != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to comment as another user")
    
    # Insert comment
    insert_query = """
    INSERT INTO comment_ (time_, tweetid, username, content_) 
    VALUES (CURRENT_TIMESTAMP, %s, %s, %s)
    """
    
    execute_query(insert_query, (tweet_id, username, content), fetch=False, commit=True)
    
    return {"status": "success", "message": "Comment added"}

@app.get("/comments_by_tweeter_id/{tweet_id}")
def get_comments(tweet_id: int, current_user: str = Depends(get_current_user)):
    query = """
    SELECT comment_.time_, comment_._id, comment_.tweetid, comment_.content_, 
           users.username, CONCAT(users.fname, ' ', users.lname) AS author, users.photo AS userphoto 
    FROM comment_ INNER JOIN users ON
    comment_.username = users.username AND comment_.tweetid = %s
    ORDER BY comment_.time_
    """
    
    data = execute_query(query, (tweet_id,))
    return data

@app.get("/delete_comment/{comment_id}")
def delete_comment(comment_id: int, current_user: str = Depends(get_current_user)):
    # Check if comment exists and belongs to current user
    check_query = "SELECT _id, username FROM comment_ WHERE _id = %s"
    comment = execute_query(check_query, (comment_id,))
    
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    if comment[0]["username"] != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to delete this comment")
    
    delete_query = "DELETE FROM comment_ WHERE _id = %s"
    execute_query(delete_query, (comment_id,), fetch=False, commit=True)
    
    return {"status": "success", "message": "Comment deleted"}

# Follow Endpoints
@app.get("/new_follow")
def follow_user(curuser: str, user: str, current_user: str = Depends(get_current_user)):
    # Ensure user is following as themselves
    if curuser != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to follow as another user")
    
    # Check if already following
    check_query = "SELECT * FROM follows WHERE follower = %s AND follows = %s"
    existing_follow = execute_query(check_query, (curuser, user))
    
    if existing_follow:
        return {"status": "info", "message": "Already following"}
    
    # Insert follow
    insert_query = "INSERT INTO follows (follower, follows) VALUES (%s, %s)"
    execute_query(insert_query, (curuser, user), fetch=False, commit=True)
    
    return {"status": "success", "message": "User followed", "curuser": curuser, "user": user}

@app.get("/new_unfollow")
def unfollow_user(curuser: str, user: str, current_user: str = Depends(get_current_user)):
    # Ensure user is unfollowing as themselves
    if curuser != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to unfollow as another user")
    
    # Delete follow
    delete_query = "DELETE FROM follows WHERE follower = %s AND follows = %s"
    execute_query(delete_query, (curuser, user), fetch=False, commit=True)
    
    return {"status": "success", "message": "User unfollowed", "curuser": curuser, "user": user}

@app.get("/is_following")
def check_following(curuser: str, user: str, current_user: str = Depends(get_current_user)):
    query = "SELECT * FROM follows WHERE follower = %s AND follows = %s"
    data = execute_query(query, (curuser, user))
    
    is_following = len(data) > 0
    
    return {"is_following": is_following, "curuser": curuser, "user": user}

# Poll Endpoints
@app.post("/new_poll")
async def create_poll(request: Request, current_user: str = Depends(get_current_user)):
    form_data = await request.form()
    data = dict(form_data)
    
    # Ensure user is creating poll as themselves
    if data["username"] != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to create poll as another user")
    
    # Get next poll id
    id_query = "SELECT COALESCE(MAX(id_), 0) + 1 AS next_id FROM poll"
    next_id_data = execute_query(id_query)
    poll_id = next_id_data[0]["next_id"] if next_id_data else 1
    
    # Insert poll
    poll_query = """
    INSERT INTO poll (id_, content_, poll_by, time_) 
    VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
    """
    execute_query(poll_query, (poll_id, data["Question"], data["username"]), fetch=False, commit=True)
    
    # Insert options
    option_query = "INSERT INTO poll_option (poll_id, option_) VALUES (%s, %s)"
    execute_query(option_query, (poll_id, data["optiona"]), fetch=False, commit=True)
    execute_query(option_query, (poll_id, data["optionb"]), fetch=False, commit=True)
    
    if data.get("optionc") and data["optionc"] != '':
        execute_query(option_query, (poll_id, data["optionc"]), fetch=False, commit=True)
    
    return {"status": "success", "message": "Poll created", "poll_id": poll_id}

@app.get("/poll/{poll_id}")
def get_poll(poll_id: int, current_user: str = Depends(get_current_user)):
    # Get poll details
    poll_query = """
    SELECT poll.id_ AS poll_id, poll.content_, poll.poll_by, poll_option.option_
    FROM poll_option INNER JOIN poll ON poll_option.poll_id = poll.id_
    WHERE poll.id_ = %s
    """
    poll_data = execute_query(poll_query, (poll_id,))
    
    if not poll_data:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    # Get vote counts
    vote_query = """
    SELECT poll_option_, COUNT(poll_option_) AS count, poll_id
    FROM vote
    WHERE poll_id = %s
    GROUP BY poll_id, poll_option_
    """
    vote_data = execute_query(vote_query, (poll_id,))
    
    # Get voters
    voters_query = "SELECT username FROM vote WHERE poll_id = %s"
    voters_data = execute_query(voters_query, (poll_id,))
    
    voted_users = [voter["username"] for voter in voters_data]
    
    question = poll_data[0]["content_"]
    user = poll_data[0]["poll_by"]
    options = [item["option_"] for item in poll_data]
    
    vote_counts = [(item["poll_option_"], item["count"]) for item in vote_data]
    
    return {
        "question": question,
        "author": user,
        "options": options,
        "count": vote_counts,
        "voted": voted_users
    }

@app.post("/cast_vote")
async def cast_vote(
    username: str = Form(...),
    poll_id: int = Form(...),
    option: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    # Ensure user is voting as themselves
    if username != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to vote as another user")
    
    # Check if already voted
    check_query = "SELECT * FROM vote WHERE username = %s AND poll_id = %s"
    existing_vote = execute_query(check_query, (username, poll_id))
    
    if existing_vote:
        return {"status": "info", "message": "Already voted"}
    
    # Insert vote
    insert_query = "INSERT INTO vote (username, poll_id, poll_option_) VALUES (%s, %s, %s)"
    execute_query(insert_query, (username, poll_id, option), fetch=False, commit=True)
    
    return {"status": "success", "message": "Vote cast"}

@app.get("/poll_feed")
def get_poll_feed(current_user: str = Depends(get_current_user)):
    query = """
    SELECT poll.id_, poll.content_, poll.poll_by, users.photo, 
           CONCAT(users.fname, ' ', users.lname) AS name, users.username 
    FROM poll
    INNER JOIN users ON users.username = poll.poll_by
    ORDER BY poll.time_ DESC
    """
    
    data = execute_query(query)
    return data

@app.get("/delete_poll/{poll_id}")
def delete_poll(poll_id: int, current_user: str = Depends(get_current_user)):
    # Check if poll exists and belongs to current user
    check_query = "SELECT id_, poll_by FROM poll WHERE id_ = %s"
    poll = execute_query(check_query, (poll_id,))
    
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    if poll[0]["poll_by"] != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to delete this poll")
    
    # Delete poll (cascade should handle related records)
    delete_query = "DELETE FROM poll WHERE id_ = %s"
    execute_query(delete_query, (poll_id,), fetch=False, commit=True)
    
    return {"status": "success", "message": "Poll deleted"}

# Group Endpoints
@app.post("/new_group")
async def create_group(
    admin: str = Form(...),
    groupname: str = Form(...),
    groupbio: str = Form(...),
    groupphoto: Optional[UploadFile] = File(None),
    current_user: str = Depends(get_current_user)
):
    # Ensure user is creating group as themselves
    if admin != current_user:
        raise HTTPException(status_code=403, detail="Not authorized to create group as another user")
    
    # Process photo if provided
    photo_base64 = ""
    if groupphoto:
        # Just get the base64 directly - no need for intermediate hex conversion
        photo_base64 = binary_from_photo_object(groupphoto)
    
    # Check if group already exists
    check_query = "SELECT grpname FROM group_ WHERE grpname = %s"
    existing_group = execute_query(check_query, (groupname,))
    
    if existing_group:
        raise HTTPException(status_code=409, detail="Group already exists")
    
    # Insert group
    insert_query = """
    INSERT INTO group_ (grpname, admin, photo, bio) 
    VALUES (%s, %s, %s, %s)
    """
    execute_query(insert_query, (groupname, admin, photo_base64, groupbio), fetch=False, commit=True)
    
    # Add admin as member
    member_query = "INSERT INTO group_members (grp_name, grpmem) VALUES (%s, %s)"
    execute_query(member_query, (groupname, admin), fetch=False, commit=True)
    
    return {"status": "success", "message": "Group created", "groupname": groupname}

@app.get("/all_groups")
def get_all_groups(current_user: str = Depends(get_current_user)):
    query = "SELECT grpname, photo FROM group_"
    data = execute_query(query)
    return data

@app.get("/group_detail/{group}/{user}")
def get_group_detail(group: str, user: str):
    # Get group info
    group_query = "SELECT * FROM group_ WHERE grpname = %s"
    group_data = execute_query(group_query, (group,))
    
    if not group_data:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Check if user is member
    member_query = "SELECT * FROM group_members WHERE grp_name = %s AND grpmem = %s"
    member_data = execute_query(member_query, (group, user))
    is_member = len(member_data) > 0
    
    # Get all members
    members_query = """
    SELECT group_members.grp_name, users.username, users.photo 
    FROM group_members 
    INNER JOIN users ON users.username = group_members.grpmem
    WHERE grp_name = %s
    """
    members_data = execute_query(members_query, (group,))
    
    return {
        "data": group_data,
        "isMember": is_member,
        "members": members_data
    }

@app.get("/user_following/{username}")
def get_user_following(username: str):
    """Get all users that a specific user is following"""
    query = """
    SELECT users.username, users.photo, CONCAT(users.fname, ' ', users.lname) AS full_name 
    FROM follows 
    INNER JOIN users ON follows.follows = users.username 
    WHERE follows.follower = %s
    ORDER BY users.username
    """
    
    data = execute_query(query, (username,))
    return data


# User Posts Endpoint
@app.get("/user_posts/{username}")
def get_user_posts(username: str):
    """Get all posts by a specific user"""
    query = """
    SELECT tweet.tweetid, tweet.content_, tweet.photo, tweet.time_,
           users.username, CONCAT(users.fname, ' ', users.lname) AS author, users.photo AS userphoto
    FROM tweet
    INNER JOIN users ON tweet.author = users.username
    WHERE users.username = %s
    ORDER BY tweet.time_ DESC
    """
    
    data = execute_query(query, (username,))
    return data

# Group Members Endpoint
@app.get("/group_members/{group_name}")
def get_group_members(group_name: str):
    """Get all members of a specific group"""
    query = """
    SELECT users.username, CONCAT(users.fname, ' ', users.lname) AS full_name, users.photo
    FROM group_members
    INNER JOIN users ON group_members.grpmem = users.username
    WHERE group_members.grp_name = %s
    ORDER BY users.username
    """
    
    data = execute_query(query, (group_name,))
    return data

@app.get("/group_posts/{group_name}")
async def get_group_posts(group_name: str):
    try:
        connection = pymysql.connect(**DB_CONFIG)
        with connection.cursor() as cursor:
            # Query should use group_name to filter posts
            query = """
            SELECT tweet.tweetid, tweet.content_, tweet.photo, tweet.time_,
                   users.username, CONCAT(users.fname, ' ', users.lname) AS author, users.photo AS userphoto
            FROM tweet
            INNER JOIN users ON tweet.author = users.username
            WHERE tweet.group_name = %s
            ORDER BY tweet.time_ DESC
            """
            cursor.execute(query, (group_name,))
            posts = cursor.fetchall()
            
            # Convert datetime objects to ISO format
            for post in posts:
                if post.get('time_'):
                    post['time_'] = post['time_'].isoformat()
                
                # Convert photo to URL if needed
                if post.get('photo'):
                    post['photo'] = f"/images/{post['tweetid']}.jpg"  # Or however you handle images
                
                if post.get('userphoto'):
                    post['userphoto'] = f"/profiles/{post['username']}.jpg"  # Or however you handle profile photos
            
            return posts
    except Exception as e:
        print(f"Error fetching group posts: {e}")
        return {"error": str(e)}
    finally:
        connection.close()

@app.post("/new_post")
async def create_post(
    username: str = Form(...),
    content: str = Form(...),
    group_name: Optional[str] = Form(None),
    photo: Optional[UploadFile] = File(None)
):
    """Create a new post (tweet), optionally in a group"""
    # Process photo if provided
    photo_base64 = ""
    if photo:
        # Just get the base64 directly - no need for intermediate hex conversion
        photo_base64 = binary_from_photo_object(photo)
    
    # Get next tweet ID
    id_query = "SELECT COALESCE(MAX(tweetid), 0) + 1 AS next_id FROM tweet"
    next_id_data = execute_query(id_query)
    tweet_id = next_id_data[0]["next_id"] if next_id_data else 1
    
    # Insert new tweet/post
    if group_name:
        # Check if user is member of the group
        check_query = "SELECT * FROM group_members WHERE grp_name = %s AND grpmem = %s"
        is_member = execute_query(check_query, (group_name, username))
        
        if not is_member:
            raise HTTPException(status_code=403, detail="User is not a member of this group")
        
        insert_query = """
        INSERT INTO tweet (tweetid, content_, photo, time_, author, group_name)
        VALUES (%s, %s, %s, CURRENT_TIMESTAMP, %s, %s)
        """
        params = (tweet_id, content, photo_base64 if photo_base64 else None, username, group_name)
    else:
        insert_query = """
        INSERT INTO tweet (tweetid, content_, photo, time_, author)
        VALUES (%s, %s, %s, CURRENT_TIMESTAMP, %s)
        """
        params = (tweet_id, content, photo_base64 if photo_base64 else None, username)
    
    execute_query(insert_query, params, fetch=False, commit=True)
    
    return {"status": "success", "message": "Post created", "post_id": tweet_id}

@app.post("/join_group")
async def join_group(
    grpname: str = Form(...),
    username: str = Form(...)
):
    # Check if already member
    check_query = "SELECT * FROM group_members WHERE grp_name = %s AND grpmem = %s"
    existing_member = execute_query(check_query, (grpname, username))
    
    if existing_member:
        return {"status": "info", "message": "Already a member"}
    
    # Insert member
    insert_query = "INSERT INTO group_members (grp_name, grpmem) VALUES (%s, %s)"
    execute_query(insert_query, (grpname, username), fetch=False, commit=True)
    
    return {"status": "success", "message": "Joined group"}

@app.post("/leave_group")
async def leave_group(
    grpname: str = Form(...),
    username: str = Form(...)
):
    # Check if admin
    admin_query = "SELECT admin FROM group_ WHERE grpname = %s"
    admin_data = execute_query(admin_query, (grpname,))
    
    if admin_data and admin_data[0]["admin"] == username:
        return {"status": "error", "message": "Admin cannot leave group"}
    
    # Delete member
    delete_query = "DELETE FROM group_members WHERE grp_name = %s AND grpmem = %s"
    execute_query(delete_query, (grpname, username), fetch=False, commit=True)
    
    return {"status": "success", "message": "Left group"}

# Chat Endpoints
@app.get("/get_chat/{user1}/{user2}")
def get_chat(user1: str, user2: str):
    query = """
    SELECT sender, receiver, msg, time_
    FROM chat 
    WHERE (sender = %s AND receiver = %s) OR (sender = %s AND receiver = %s)
    ORDER BY time_ ASC
    """
    
    data = execute_query(query, (user1, user2, user2, user1))
    return data

@app.post("/new_chat_msg")
async def new_chat_msg(
    sender: str = Form(...),
    receiver: str = Form(...),
    msg: str = Form(...)
):
    insert_query = """
    INSERT INTO chat (sender, receiver, msg, time_) 
    VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
    """
    
    execute_query(insert_query, (sender, receiver, msg), fetch=False, commit=True)
    
    return {"status": "success", "message": "Message sent"}

# User listing
@app.get("/all_users")
def get_all_users():
    query = """
    SELECT users.username, CONCAT(users.fname, ' ', users.lname) AS author, 
           users.photo AS userphoto 
    FROM users
    """
    
    data = execute_query(query)
    return data

# Authentication
@app.get("/auth/{username}")
def auth(username: str):
    query = "SELECT mailid FROM users WHERE username = %s"
    data = execute_query(query, (username,))
    
    if not data:
        raise HTTPException(status_code=404, detail="User not found")
        
    return data


# Add these endpoints to your FastAPI app

# Group Chat Endpoints
@app.get("/group_chat/{group_name}")
def get_group_chat(group_name: str):
    """Get all messages for a specific group"""
    query = """
    SELECT group_chat.id, group_chat.sender, group_chat.message, group_chat.time_,
           users.photo AS user_photo
    FROM group_chat 
    INNER JOIN users ON group_chat.sender = users.username
    WHERE group_chat.grp_name = %s
    ORDER BY group_chat.time_ ASC
    """
    
    data = execute_query(query, (group_name,))
    return data

@app.post("/send_group_message")
async def send_group_message(
    grp_name: str = Form(...),
    sender: str = Form(...),
    message: str = Form(...)
):
    """Send a message to a group chat"""
    # Check if user is a member of the group
    check_query = "SELECT * FROM group_members WHERE grp_name = %s AND grpmem = %s"
    is_member = execute_query(check_query, (grp_name, sender))
    
    if not is_member:
        raise HTTPException(status_code=403, detail="User is not a member of this group")
    
    # Insert message
    insert_query = """
    INSERT INTO group_chat (grp_name, sender, message) 
    VALUES (%s, %s, %s)
    """
    execute_query(insert_query, (grp_name, sender, message), fetch=False, commit=True)
    
    return {"status": "success", "message": "Message sent to group"}

# Group Join Request Endpoints
@app.post("/request_join_group")
async def request_join_group(
    grpname: str = Form(...),
    username: str = Form(...)
):
    """Request to join a group"""
    # Check if already member
    check_member_query = "SELECT * FROM group_members WHERE grp_name = %s AND grpmem = %s"
    existing_member = execute_query(check_member_query, (grpname, username))
    
    if existing_member:
        return {"status": "info", "message": "Already a member"}
    
    # Check if already requested
    check_request_query = "SELECT * FROM group_requests WHERE grp_name = %s AND username = %s"
    existing_request = execute_query(check_request_query, (grpname, username))
    
    if existing_request:
        return {"status": "info", "message": "Request already sent"}
    
    # Insert request with default status = 'pending'
    insert_query = """
    INSERT INTO group_requests (grp_name, username, status) 
    VALUES (%s, %s, 'pending')
    """
    execute_query(insert_query, (grpname, username), fetch=False, commit=True)
    
    return {"status": "success", "message": "Join request sent"}

@app.get("/group_join_requests/{group_name}")
def get_group_requests(group_name: str):
    """Get all pending join requests for a group"""
    query = """
    SELECT group_requests.id, group_requests.username, group_requests.request_time,
           group_requests.status, group_requests.grp_name
    FROM group_requests 
    WHERE group_requests.grp_name = %s AND group_requests.status = 'pending'
    ORDER BY group_requests.request_time DESC
    """
    
    data = execute_query(query, (group_name,))
    return data

@app.post("/approve_group_request")
async def approve_group_request(
    request_id: int = Form(...),
    action: str = Form(...)  # 'approved' or 'rejected'
):
    """Approve or reject a group join request"""
    # Get request details
    check_query = "SELECT grp_name, username FROM group_requests WHERE id = %s AND status = 'pending'"
    request_data = execute_query(check_query, (request_id,))
    
    if not request_data:
        raise HTTPException(status_code=404, detail="Request not found or already processed")
    
    grp_name = request_data[0]["grp_name"]
    username = request_data[0]["username"]
    
    # Update request status
    update_query = "UPDATE group_requests SET status = %s WHERE id = %s"
    execute_query(update_query, (action, request_id), fetch=False, commit=True)
    
    # If approved, add user to group members
    if action == 'approved':
        insert_query = "INSERT INTO group_members (grp_name, grpmem) VALUES (%s, %s)"
        execute_query(insert_query, (grp_name, username), fetch=False, commit=True)
        return {"status": "success", "message": "Request approved and user added to group"}
    else:
        return {"status": "success", "message": "Request rejected"}

# Follow Request Endpoints
@app.post("/request_follow/{requester}/{target}")
async def request_follow(requester: str, target: str):
    """Send a follow request"""
    # Check if follow request already exists
    check_query = """
    SELECT id FROM follow_requests 
    WHERE requester = %s AND target = %s AND status = 'pending'
    """
    existing_request = execute_query(check_query, (requester, target))
    
    if existing_request:
        raise HTTPException(status_code=400, detail="Follow request already pending")
    
    # Check if already following
    check_following_query = "SELECT * FROM follows WHERE follower = %s AND follows = %s"
    already_following = execute_query(check_following_query, (requester, target))
    
    if already_following:
        raise HTTPException(status_code=400, detail="Already following this user")
    
    # Create follow request
    insert_query = """
    INSERT INTO follow_requests 
    (requester, target, status, request_time) 
    VALUES (%s, %s, 'pending', NOW())
    """
    execute_query(insert_query, (requester, target), fetch=False, commit=True)
    
    return {"status": "success", "message": "Follow request sent"}


@app.get("/follow_requests/{username}")
def get_follow_requests(username: str):
    """Get all pending follow requests for a user"""
    query = """
    SELECT follow_requests.id, follow_requests.requester, follow_requests.request_time,
           follow_requests.status, follow_requests.target,
           users.photo AS user_photo
    FROM follow_requests 
    INNER JOIN users ON follow_requests.requester = users.username
    WHERE follow_requests.target = %s AND follow_requests.status = 'pending'
    ORDER BY follow_requests.request_time DESC
    """
    
    data = execute_query(query, (username,))
    return data

@app.post("/approve_follow_request")
async def approve_follow_request(
    request_id: int = Form(...),
    action: str = Form(...)  # 'approved' or 'rejected'
):
    """Approve or reject a follow request"""
    # Get request details
    check_query = "SELECT requester, target, status FROM follow_requests WHERE id = %s"
    request_data = execute_query(check_query, (request_id,))
    
    if not request_data:
        raise HTTPException(status_code=404, detail="Request not found")
    
    requester = request_data[0]["requester"]
    target = request_data[0]["target"]
    
    # Update request status
    update_query = "UPDATE follow_requests SET status = %s WHERE id = %s"
    execute_query(update_query, (action, request_id), fetch=False, commit=True)
    
    # If approved, add follow relationship (only if it doesn't already exist)
    if action == 'approved':
        # First check if follow relationship already exists
        check_follow_query = "SELECT * FROM follows WHERE follower = %s AND follows = %s"
        existing_follow = execute_query(check_follow_query, (requester, target))
        
        if not existing_follow:
            insert_query = "INSERT INTO follows (follower, follows) VALUES (%s, %s)"
            execute_query(insert_query, (requester, target), fetch=False, commit=True)
            return {"status": "success", "message": "Follow request approved"}
        else:
            # If follow already exists, just return success
            return {"status": "success", "message": "Follow request approved (already following)"}
    else:
        return {"status": "success", "message": "Follow request rejected"}
    

# Remove member from group (admin function)
@app.post("/remove_group_member")
async def remove_group_member(
    grp_name: str = Form(...),
    admin: str = Form(...),  # Current user (must be admin)
    username: str = Form(...)  # User to remove
):
    """Remove a member from a group"""
    # Verify admin status
    admin_query = "SELECT admin FROM group_ WHERE grpname = %s"
    admin_data = execute_query(admin_query, (grp_name,))
    
    if not admin_data or admin_data[0]["admin"] != admin:
        raise HTTPException(status_code=403, detail="Only admin can remove members")
    
    # Can't remove admin
    if username == admin:
        raise HTTPException(status_code=400, detail="Admin cannot be removed")
    
    # Remove member
    delete_query = "DELETE FROM group_members WHERE grp_name = %s AND grpmem = %s"
    execute_query(delete_query, (grp_name, username), fetch=False, commit=True)
    
    return {"status": "success", "message": "Member removed from group"}

# Remove follower (user function) 
@app.post("/remove_follower")
async def remove_follower(
    user: str = Form(...),  # Current user
    follower: str = Form(...)  # Follower to remove
):
    """Remove a follower"""
    # Remove follow relationship
    delete_query = "DELETE FROM follows WHERE follower = %s AND follows = %s"
    execute_query(delete_query, (follower, user), fetch=False, commit=True)
    
    return {"status": "success", "message": "Follower removed"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000,reload=True)