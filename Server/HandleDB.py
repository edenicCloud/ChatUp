import bcrypt as bcrypt
from pymongo.mongo_client import MongoClient
from Chat import Group
from Chat import P2PChat
import os

uri = os.getenv("MONGO_DB_URI")
client = MongoClient(uri)
db = client["ChatUpDB"]
chats_collection = db.ChatCollection
users_collection = db.UserCollection  # Collection for users


def create_user(username, password):
    """Adds new user to DB"""
    new_user = {
        "username": username,
        "is_online": False,
        "chats": [],
        "awaiting_messages": {},
        "characteristics": "",
        "password_hash": bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        "new_chats": {},
        "characteristics_count": 0

    }

    users_collection.insert_one(new_user)
    print(f"User {username} created successfully.")
    return True


def create_p2p_chat(name1, name2):
    """Adds 1:1 chat to DB"""
    if chats_collection.find_one({"user1": name1, "user2": name2}) or chats_collection.find_one(
            {"user1": name2, "user2": name1}):
        return False
    chat = P2PChat(name1, name2)
    result = chats_collection.insert_one(chat.to_dict())  # Insert chat
    chat_id = result.inserted_id  # Get the _id of the inserted chat

    # Link chat to both users
    for username in [name1, name2]:
        users_collection.update_one(
            {"username": username},
            {"$push": {"chats": chat_id}},
            upsert=True  # Create user if not exists
        )
    print(f"P2P chat saved with ID {chat_id} and linked to users {name1} and {name2}.")
    return True


def create_group_chat(name, admin, members):
    """Adds new group chat to DB"""
    if chats_collection.find_one({"name": name}):
        return False
    chat = Group(name, admin, members)
    result = chats_collection.insert_one(chat.to_dict())  # Insert chat
    chat_id = result.inserted_id

    # Link to admin and members
    for user in [admin] + members:
        users_collection.update_one(
            {"username": user.strip()},
            {"$push": {"chats": chat_id}},
            upsert=True
        )
    print(f"Group chat saved with ID {chat_id} and linked to members.")
    return True


def add_to_characteristics(username, new_characteristic):
    """Adds new user characteristic to DB"""
    _, _, bare_characteristic = str(new_characteristic).partition(":")
    document = users_collection.find_one({"username": username})
    if document["characteristics_count"] < 30:
        current = document["characteristics"]
        if current:
            updated = current + "','" + bare_characteristic
        else:
            updated = "'" + bare_characteristic
        users_collection.update_one(
            {"username": username},
            {"$set": {"characteristics": updated}}
        )
        users_collection.update_one(
            {"username": username},
            {"$inc": {"characteristics_count": 1}}
        )


def user_exists(username):
    """checks if user exists"""
    user = find_user("username", username)
    if user:
        return True
    return False


# find user/chat functions

def find_user(field, value):
    user = users_collection.find_one({field: value})
    return user


def advanced_find_user(param1, param2):
    search_results = users_collection.find(param1, param2)
    return search_results


def find_chat(field, value):
    result = chats_collection.find_one({field: value})
    return result


def advanced_find_chat(value, chat_ids):
    chat = chats_collection.find_one({
        "_id": {"$in": chat_ids},
        "$or": value
    })
    return chat


# set field in DB functions

def set_user_document_field(username, field, value):
    users_collection.update_one(
        {"username": username},
        {"$set": {field: value}}
    )


def add_to_user_document_field(username, field, value):
    users_collection.update_one(
        {"username": username},
        {"$push": {field: value}},
        upsert=True
    )


def add_to_chat_document_field(chat_id, field, value):
    chats_collection.update_one(
        {"_id": chat_id},
        {"$push": {field: value}}
    )
