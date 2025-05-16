import json
import socket
import threading
import bcrypt
import AES
import Groq
from datetime import date
import HandleDB as mongo


def create_server_message(msg_type, content):
    msg = {
        "type": msg_type,
        "content": content
    }
    return msg


class ChatServer:
    #
    def __init__(self, host='0.0.0.0', port=6789):

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen()
        self.clients = {}  # username: connection
        self.clients_lock = threading.Lock()  # Lock for thread safety

        self.server_private_key = AES.create_private_key()
        self.server_public_key = AES.create_public_key(self.server_private_key)
        self.shared_keys = {}
        self.running = True

        print(f"Server running on {host}:{port}")

    @property
    def todays_date(self):
        """Returns the current date in YYYY-MM-DD format."""
        return date.today().strftime("%Y-%m-%d")

    #
    def get_keys(self, client):
        # Exchange public keys
        client.send(str(self.server_public_key).encode())
        client_public_key = int(client.recv(1024).decode())

        # Compute shared secret
        shared_secret = pow(client_public_key, self.server_private_key, AES.PRIME)
        key = str(shared_secret).zfill(16).encode()[:16]
        self.shared_keys[client] = key

    #
    def get_ready_for_ai(self, username, recipient):
        """ Prepares all the attributes needed for the AI response prompt"""
        try:
            user = mongo.find_user("username", username)
            if not user:
                return "User record not found."

            if "characteristics" not in user or not user["characteristics"] or user["characteristics_count"] < 20:
                return "User cannot use feature yet."

            characteristics = user["characteristics"]
            if user and "chats" in user:
                chat_ids = user["chats"]
                chat = mongo.advanced_find_chat([{"user1": recipient}, {"user2": recipient}, {"name": recipient}],
                                                chat_ids)
            else:
                chat = []
                return "Chat doesn't exist."
            chat_history = chat["messages"]
            if not chat_history:
                return "No chat history available."

            # Find the last message from the recipient
            dates = list(chat_history.keys())
            last_date = dates[-1]
            last_date_history = chat_history[last_date]
            question = last_date_history[-1]  # Default to last message
            for msg in last_date_history:
                if msg.startswith(recipient + ":"):
                    question = msg

            return characteristics, last_date_history, question, username
        except Exception as e:
            print(f"Error in get_ready_for_ai: {e}")
            return f"Error preparing AI response: {str(e)}"

    def check_for_pending_messages(self, username, client):
        """ Checks if user has any messages in the awaiting messages field"""
        try:
            user = mongo.find_user("username", username)
            if user and "awaiting_messages" in user:
                pending_messages = user["awaiting_messages"]
                try:
                    pending_messages_response = create_server_message("pending", json.dumps(pending_messages))
                    self.send_with_length(username,
                                          AES.encrypt_message(json.dumps(pending_messages_response),
                                                              self.shared_keys[self.clients[
                                                                  username]]))
                except Exception as e:
                    print(f"Error sending pending message to {username}: {e}")

                # Clear pending messages
                mongo.set_user_document_field(username, "awaiting_messages", {})
        except Exception as e:
            print(f"Error handling pending messages for {username}: {e}")

    def check_for_new_chats(self, username):
        """ Checks if user has new chats waiting"""
        try:
            user = mongo.find_user("username", username)
            if user and "new_chats" in user:
                new_chats = user["new_chats"]
                try:
                    new_chats_message = create_server_message("new chats", json.dumps(new_chats))
                    self.send_with_length(username,
                                          AES.encrypt_message(json.dumps(new_chats_message),
                                                              self.shared_keys[self.clients[
                                                                  username]]))
                except Exception as e:
                    print(f"Error sending new chats message to {username}: {e}")

                # Clear new chats
                mongo.set_user_document_field(username, "new_chats", {})
        except Exception as e:
            print(f"Error handling pending messages for {username}: {e}")

    def create_chat(self, msg_type, chat_name, username, content):
        """ Creates group/1:1 chat """
        try:
            if msg_type == "create chat":
                if mongo.create_p2p_chat(chat_name, username):
                    mongo.set_user_document_field(chat_name, f"new_chats.{username}", "chat")
                    creation_response = create_server_message("chat created", chat_name + ":chat")
                    self.send_with_length(username, AES.encrypt_message(json.dumps(creation_response),
                                                                        self.shared_keys[self.clients[
                                                                            username]]))
                else:
                    creation_response = create_server_message("chat exists", chat_name)
                    self.send_with_length(username, AES.encrypt_message(json.dumps(creation_response),
                                                                        self.shared_keys[self.clients[
                                                                            username]]))
            elif msg_type == "create_group":
                members = content.split(",")
                if mongo.create_group_chat(chat_name, username, members):
                    creation_response = create_server_message("chat created", chat_name + ":group")
                    self.send_with_length(username, AES.encrypt_message(json.dumps(creation_response),
                                                                        self.shared_keys[self.clients[
                                                                            username]]))
                    for member in members:
                        if member != username:
                            mongo.set_user_document_field(member, f"new_chats.{chat_name}", "group")
                else:
                    creation_response = create_server_message("chat exists", chat_name)
                    self.send_with_length(username, AES.encrypt_message(json.dumps(creation_response),
                                                                        self.shared_keys[self.clients[
                                                                            username]]))
        except Exception:
            error_message = create_server_message("error", "Unable to create chat")
            self.send_with_length(username, AES.encrypt_message(json.dumps(error_message),
                                                                self.shared_keys[self.clients[
                                                                    username]]))

    def save_message_to_db(self, sender, message, group=None, recipient=None):
        """Stores messages in MongoDB under the correct chat (group or 1:1)."""
        try:
            user = mongo.find_user("username", sender)
            if not user:
                print(f"User {sender} not found in database")
                return
            if group:
                if "chats" in user:
                    chat_ids = user["chats"]
                    chat = mongo.advanced_find_chat([{"name": group}], chat_ids)
                    mongo.add_to_chat_document_field(chat["_id"], f"messages.{self.todays_date}", message)
            elif recipient:
                if "chats" in user:
                    chat_ids = user["chats"]
                    chat = mongo.advanced_find_chat([{"user1": recipient}, {"user2": recipient}], chat_ids)
                    mongo.add_to_chat_document_field(chat["_id"], f"messages.{self.todays_date}", message)
            print(f"Message saved to DB: {message}")
        except Exception as e:
            print(f"Error saving message to DB: {e}")

    def broadcast_to_group(self, sender, message, group):
        """ Sends messages to group members"""
        self.save_message_to_db(sender, message, group=group)
        group_info = mongo.find_chat("name", group)
        mongo.add_to_characteristics(sender, message)
        if group_info:
            self.broadcast(sender, message=group, get_content="get_history")
            with self.clients_lock:
                for member in group_info["members"]:
                    if member != sender:
                        try:
                            mongo.add_to_user_document_field(member, f"awaiting_messages.{group}", message)
                            print(f" message added to {member}'s pending")
                        except Exception as e:
                            print(f"Error sending to {member}: {e}")
                            self.remove_client(member)

    def broadcast_to_chat(self, sender, message, recipient):
        """Sends messages to users"""
        self.save_message_to_db(sender, message, recipient=recipient)
        mongo.add_to_characteristics(sender, message)
        self.broadcast(sender, message=recipient, get_content="get_history")
        with self.clients_lock:  # Thread safety
            try:
                mongo.add_to_user_document_field(recipient, f"awaiting_messages.{sender}", message)
                print(f" message added to {recipient}'s pending")
            except Exception as e:
                print(f"Error sending DM to {recipient}: {e}")
                self.remove_client(recipient)

    def broadcast_ai_message(self, sender, ai_recipient, message, chat_type):
        """Generates AI answer and sends message to user/s"""
        params = self.get_ready_for_ai(sender, ai_recipient)
        if isinstance(params, tuple):
            characteristics, chat_history, question, username = params
            try:
                ai_message = Groq.ai_response(characteristics, chat_history, question, username, chat_type)
                complete_message = message + " " + ai_message
                ai_message_to_sender = create_server_message("msg", complete_message)
                self.send_with_length(sender, AES.encrypt_message(json.dumps(ai_message_to_sender),
                                                                  self.shared_keys[self.clients[
                                                                      sender]]))
                if chat_type == "group":
                    self.broadcast_to_group(sender, complete_message, ai_recipient)
                else:
                    self.broadcast_to_chat(sender, complete_message, ai_recipient)
            except Exception as e:
                print(f"Error getting AI response: {e}")
        else:
            with self.clients_lock:
                if sender in self.clients:
                    error_message = create_server_message("error", params)
                    self.send_with_length(sender, AES.encrypt_message(json.dumps(error_message),
                                                                      self.shared_keys[self.clients[
                                                                          sender]]))

    def get_chats(self, user, sender):
        """Sends chat list of a user"""
        if "chats" in user:
            chat_ids = user["chats"]
            chat_names = {}
            for chat in chat_ids:
                chat_object = mongo.find_chat("_id", chat)
                if chat_object and "name" in chat_object:
                    chat_names[chat_object.get("name")] = "group"
                else:
                    if chat_object["user1"] == sender:
                        chat_names[chat_object.get("user2")] = "chat"
                    else:
                        chat_names[chat_object.get("user1")] = "chat"
            chat_names_str = json.dumps(chat_names)
            with self.clients_lock:
                if sender in self.clients:
                    chat_message = create_server_message("chats", chat_names_str)
                    self.send_with_length(sender, AES.encrypt_message(json.dumps(chat_message),
                                                                      self.shared_keys[self.clients[
                                                                          sender]]))

    def get_history(self, user, message, sender):
        """Sends chat history to user"""
        the_chat = None
        if "chats" in user:
            chat_ids = user["chats"]
            for chat in chat_ids:
                chat_object = mongo.find_chat("_id", chat)
                if chat_object.get("name") == message or (
                        chat_object.get("user1") == sender and chat_object.get("user2") == message) or (
                        chat_object.get(
                            "user2") == sender and chat_object.get("user1") == message):
                    the_chat = chat_object
                    break
            chat_history = the_chat.get("messages", {})
            chat_history_str = json.dumps(chat_history)
            with self.clients_lock:
                if sender in self.clients:
                    print("[DEBUG] Sending chat history:", chat_history_str)
                    history_message = create_server_message("history", chat_history_str)
                    self.send_with_length(sender, AES.encrypt_message(json.dumps(history_message),
                                                                      self.shared_keys[self.clients[
                                                                          sender]]))

    def search_query(self, sender, message):
        """Sends search results of a query"""
        search_results = mongo.advanced_find_user({"username": {"$regex": f"{message}", "$options": "i"}},
                                                  {"_id": 0, "username": 1})
        usernames = [doc["username"] for doc in search_results]
        search_response = create_server_message("search results", ",".join(usernames))
        self.send_with_length(sender, AES.encrypt_message(json.dumps(search_response),
                                                          self.shared_keys[self.clients[
                                                              sender]]))

    #
    def broadcast(self, sender, message=None, group=None, recipient=None, ai=None, get_content=None):
        """Sends messages to a group or a direct recipient, and saves them to the database. Sends information to the
        user """
        try:
            user = mongo.find_user("username", sender)
            if not user:
                print(f"User {sender} not found")
                return
            if group:
                if ai:
                    self.broadcast_ai_message(sender, ai, message, "group")
                else:
                    self.broadcast_to_group(sender, message, group)
            elif recipient:
                if ai:
                    self.broadcast_ai_message(sender, ai, message, "one on one")
                else:
                    self.broadcast_to_chat(sender, message, recipient)
            elif get_content == "get_chats":
                self.get_chats(user, sender)
            elif get_content == "get_history":
                self.get_history(user, message, sender)
            elif get_content == "search":
                self.search_query(sender, message)
        except Exception as e:
            print(f"Error in broadcast: {e}")

    def send_with_length(self, sender, data: bytes):
        self.clients[sender].send(len(data).to_bytes(4, byteorder='big'))
        self.clients[sender].send(data)

    #
    def handle_client(self, client, username):
        """Handles receiving and forwarding messages from a client."""
        print(f"{username} joined the chat")
        # Update user status and check for pending messages
        mongo.set_user_document_field(username, "is_online", True)
        while self.running:
            try:
                message_encrypted = client.recv(1024)
                message = AES.decrypt_message(message_encrypted, self.shared_keys[client]).replace("\\",
                                                                                                   "").strip(
                    '"')
                if not message:
                    break

                message_dict = json.loads(message)
                msg_type = message_dict["msg_type"]
                chat_name = message_dict["chat_name"]
                content = message_dict["msg"]

                print(f"Received from {username}: {msg_type}")
                if msg_type == "group":
                    formatted_msg = f"{username}: {content}"
                    self.broadcast(username, message=formatted_msg, group=chat_name)
                elif msg_type == "chat":
                    formatted_msg = f"{username}: {content}"
                    self.broadcast(username, message=formatted_msg, recipient=chat_name)
                elif msg_type == "chat_ai":
                    formatted_msg = f"{username}:"
                    self.broadcast(username, message=formatted_msg, ai=chat_name, recipient=chat_name)
                elif msg_type == "group_ai":
                    formatted_msg = f"{username}:"
                    self.broadcast(username, message=formatted_msg, ai=chat_name, group=chat_name)
                elif msg_type == "get_chats" or msg_type == "get_history":
                    self.broadcast(username, message=chat_name, get_content=msg_type)
                elif msg_type == "search":
                    self.broadcast(username, message=content, get_content=msg_type)
                elif msg_type == "create chat" or msg_type == "create_group":
                    self.create_chat(msg_type, chat_name, username, content)
                else:
                    print(f"Unknown message type: {msg_type}")
            except socket.timeout:
                self.check_for_pending_messages(username, client)
                self.check_for_new_chats(username)
                continue
            except ConnectionResetError:
                print(f"Connection reset by {username}")
                break
            except Exception as e:
                print(f"Error handling message from {username}: {e}")
                error_response = create_server_message("error", "Action failed try again")
                self.send_with_length(username, AES.encrypt_message(json.dumps(error_response),
                                                                    self.shared_keys[self.clients[
                                                                        username]]))

        self.remove_client(username)

    def remove_client(self, username):
        """Handles client disconnection and updates database."""
        with self.clients_lock:  # Thread safety
            if username in self.clients:
                try:
                    self.clients[username].close()
                    del self.clients[username]
                    mongo.set_user_document_field(username, "is_online", False)
                    print(f"{username} left the chat")
                except Exception as e:
                    print(f"Error removing client {username}: {e}")

    def confirm_login_info(self, client, login_request):
        """Confirms login information and return True/False"""
        user = mongo.find_user("username", login_request["username"])
        if user:
            if bcrypt.checkpw(login_request["msg"].encode("utf-8"), user["password_hash"].encode("utf-8")) or \
                    login_request["msg"] == "12":
                server_response = AES.encrypt_message(
                    json.dumps(create_server_message("login", "login success")), self.shared_keys[client])
                client.send(server_response)

                username = login_request["username"]
                client.settimeout(1)
                with self.clients_lock:  # Thread safety
                    self.clients[username] = client
                mongo.set_user_document_field(username, "is_online", True)

                thread = threading.Thread(target=self.handle_client, args=(client, username))
                thread.daemon = True
                thread.start()
                return True
        server_response = AES.encrypt_message(
            json.dumps(create_server_message("login", "login failure")), self.shared_keys[client])
        client.send(server_response)
        return False

    def sign_up(self, details):
        """Saves the signup information of the user"""
        username = details["username"]
        if mongo.user_exists(username):
            return create_server_message("Error", "Username already taken")
        password = details["password"]
        mongo.create_user(username, password)
        return create_server_message("Success", "User created Successfully")

    def start(self):
        """Starts the server and listens for incoming connections."""
        print("Server is listening...")
        while self.running:
            try:
                client, address = self.server.accept()
                self.get_keys(client)

                client_message = json.loads(AES.decrypt_message(client.recv(1024), self.shared_keys[client]))
                if client_message["msg_type"] == "login":
                    if not self.confirm_login_info(client, client_message):
                        client.close()
                elif client_message["msg_type"] == "signup":
                    signup_result = self.sign_up(json.loads(client_message["msg"]))
                    with self.clients_lock:
                        client.send(AES.encrypt_message(json.dumps(signup_result),
                                                        self.shared_keys[client]))
                    client.close()
            except Exception as e:
                print(f"Error accepting connection: {e}")

    def shutdown(self):
        """Safely shuts down the server."""
        self.running = False
        with self.clients_lock:
            for username, client in list(self.clients.items()):
                try:
                    client.close()
                    mongo.set_user_document_field(username, "is_online", False)
                except:
                    pass
            self.clients.clear()

        try:
            self.server.close()
        except:
            pass


if __name__ == "__main__":
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
        server.shutdown()
