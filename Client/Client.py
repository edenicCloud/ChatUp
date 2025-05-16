import json
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from PIL import Image, ImageTk
import time
from datetime import datetime, date
import AES
import Screens


def is_datetime(date_str):
    """Checks if a string is a date"""
    if not isinstance(date_str, str):
        return False
    try:
        datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f")
        return True
    except ValueError:
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
            return True
        except ValueError:
            return None


def find_all_keys_with_target_value(d: dict, target_value):
    """Finds all keys in a dict that have target_value"""
    return [key for key, value in d.items() if value == target_value]


def create_client_message(msg_type, username, content="None", chat_name="None"):
    msg = {
        "msg_type": msg_type,
        "chat_name": chat_name,
        "username": username,
        "msg": content
    }
    return msg


class Client:
    def __init__(self, master, host='127.0.0.1', port=6789):
        """Initializes the client, connects to the server, and sets up the GUI."""

        self.master = master
        self.host = host
        self.port = port
        self.sock = None
        self.username = None
        self.running = True

        self.client_private_key = AES.create_private_key()
        self.client_public_key = AES.create_public_key(self.client_private_key)
        self.server_public_key = None
        self.key = None

        self.last_conversation_date = None
        self.current_chat = ""

        self.pending_messages = {}
        self.chat_dict = {}
        self.chat_display = None

        self.master.title("ChatUp")
        self.master.geometry("800x600")
        self.master.config(bg="#778da9")

        self.create_login_screen()

    @property
    def todays_date(self):
        """Returns the current date in YYYY-MM-DD format."""
        return date.today().strftime("%Y-%m-%d")

    # connection to server and key exchange
    def connect_to_server(self):
        """Connects to the server and exchanges keys"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))

            self.get_keys()
            return True
        except socket.timeout:
            return False

    def get_keys(self):
        """Key exchange"""
        # Exchange public keys
        self.server_public_key = int(self.sock.recv(1024).decode())
        self.sock.send(str(self.client_public_key).encode())

        # Compute shared secret
        shared_secret = pow(self.server_public_key, self.client_private_key, AES.PRIME)
        self.key = str(shared_secret).zfill(16).encode()[:16]

    # log in
    def create_login_screen(self):
        """Creates the login screen for entering a username."""
        self.login_frame = tk.Frame(self.master, bg="#778da9")
        self.login_frame.pack(pady=50)

        tk.Label(self.login_frame, text="Enter Username:", font=("Arial", 12), bg="#778da9").pack()
        username_entry = tk.Entry(self.login_frame, font=("Arial", 12))
        username_entry.pack(pady=5)
        tk.Label(self.login_frame, text="Enter Password:", font=("Arial", 12), bg="#778da9").pack()
        self.password_entry = tk.Entry(self.login_frame, font=("Arial", 12), show="*")
        self.password_entry.pack(pady=5)

        login_button = tk.Button(self.login_frame, text="Login", command=lambda: self.login(username_entry),
                                 bg="#d41735", fg="white")
        login_button.pack(pady=5)
        signup_button = tk.Button(self.login_frame, text="Sign up",
                                  command=lambda: Screens.create_signup_window(self.signup),
                                  bg="#d41735", fg="white")
        signup_button.pack(pady=5)

        self.image = Image.open('Icon.png')
        self.image = self.image.resize((300, 300))
        self.image = ImageTk.PhotoImage(self.image)
        self.image_label = tk.Label(self.master, image=self.image, borderwidth=0, highlightthickness=0, bg="#778da9")
        self.image_label.pack()

    def login(self, username_entry):
        """Handles login and connects to the server."""
        self.username = username_entry.get().strip()
        if not self.username:
            messagebox.showerror("Error", "Username cannot be empty!")
            return
        threading.Thread(target=self.connect_to_server_and_load_ui).start()

    def connect_to_server_and_load_ui(self):
        """Connects to server in a background thread and loads UI if successful."""
        if self.connect_to_login():
            print("Connected successfully")
            self.master.after(0, self.load_chat_ui)

    def connect_to_login(self):
        """Attempts to connect to the chat server."""
        try:
            self.connect_to_server()

            password = self.password_entry.get().strip()
            login_request = json.dumps(create_client_message("login", self.username, content=password))
            encrypted_request = AES.encrypt_message(login_request, self.key)
            self.sock.send(encrypted_request)
            server_response = json.loads(AES.decrypt_message(self.sock.recv(1024), self.key))

            if server_response["content"] == "login success":
                print("logged in")
                try:
                    time.sleep(0.01)
                    chats_request = create_client_message("get_chats", self.username)
                    self.sock.send(AES.encrypt_message(json.dumps(chats_request), self.key))
                    chat_list_msg = self.recv_full_message()
                    chat_list_str = json.loads(AES.decrypt_message(chat_list_msg, self.key))["content"]
                    self.chat_dict = json.loads(chat_list_str)
                except Exception as e:
                    print(f"Error getting chat list: {e}")
                    self.chat_dict = {}

                threading.Thread(target=self.receive_messages, daemon=True).start()
                return True
            else:
                tk.Label(self.login_frame, text="Data above is incorrect", font=("Arial", 12), foreground="red",
                         bg="#778da9").pack()
                return False

        except Exception as e:
            print("Connection Error", f"Couldn't connect to the server: {e}")
            return False

    # sign up
    def signup(self, username, password):
        """Handles signup and connects to the server."""
        if not username:
            messagebox.showerror("Error", "Username cannot be empty!")
            return
        details_dict = {
            "username": username,
            "password": password,
        }
        details_str = json.dumps(details_dict)
        threading.Thread(target=lambda: self.connect_to_server_and_signup(details_str)).start()

    def connect_to_server_and_signup(self, details):
        """Connects to server in a background thread and loads UI if successful."""
        if self.connect_to_server():
            signup_request = create_client_message("signup", "None", content=details)
            self.sock.send(AES.encrypt_message(json.dumps(signup_request), self.key))

            server_response = json.loads(AES.decrypt_message(self.sock.recv(1024), self.key))
            messagebox.showinfo(server_response["type"], server_response["content"])

    # ui
    def load_chat_ui(self):
        """Loads the chat UI."""
        print("Loading chat UI")
        self.login_frame.destroy()
        self.image_label.destroy()

        self.left_panel = tk.Frame(self.master, width=200, bg="#1b263b")
        self.left_panel.pack(side=tk.LEFT, fill=tk.Y)

        header_frame = tk.Frame(self.left_panel, bg="#1b263b")
        header_frame.pack(pady=10, padx=5, anchor="w")  # Left aligned

        menu = tk.Menu(self.master, tearoff=0)
        menu.add_command(label="New Group",
                         command=lambda: Screens.create_group_creation_window(
                             find_all_keys_with_target_value(self.chat_dict, "chat"),
                             self.request_chat_callback))
        menu.add_command(label="Search", command=lambda: Screens.create_search_ui(self.search_users,
                                                                                  self.request_chat_callback))

        def show_menu(event=None):
            x = square_button.winfo_rootx()
            y = square_button.winfo_rooty() + square_button.winfo_height()
            menu.tk_popup(x, y)

        square_button = tk.Button(header_frame, text="☰", width=2, height=1,
                                  bg="white", fg="#1b263b", font=("Arial", 10, "bold"),
                                  command=show_menu)  # define this method
        square_button.pack(side=tk.LEFT, padx=(0, 8))

        contacts_label = tk.Label(header_frame, text=f"{self.username}'s Chats", bg="#1b263b", fg="white",
                                  font=("Arial", 14))
        contacts_label.pack(side=tk.LEFT)

        style = ttk.Style()
        style.configure("Treeview",
                        font=("Arial", 12),
                        rowheight=50,  # Increased row height
                        background="#778da9",
                        fieldbackground="#778da9",
                        foreground="white")
        style.configure("Treeview.Heading", font=("Arial", 14, "bold"), background="#1b263b", foreground="white")

        # Chat List (Treeview)
        self.contacts_list = ttk.Treeview(self.left_panel, show="tree", selectmode="browse")
        self.contacts_list.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Add chats to Treeview
        for chat in self.chat_dict.keys():
            if chat.strip():
                self.contacts_list.insert("", "end", iid=chat, text=f"  {chat}")

        self.contacts_list.bind("<<TreeviewSelect>>", self.enter_chat)

        # Right Panel (Chat Area)
        self.right_panel = tk.Frame(self.master, bg="white")
        self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        print("right panel packed")

        self.chat_label = tk.Label(self.right_panel, bg="#1b263b", fg="white", font=("Arial", 14), height=2)
        self.chat_label.pack(pady=0, fill=tk.BOTH)

    def enter_chat(self, event=None, chat_name=None):
        """Handles clicking on a chat to open it."""

        if self.current_chat == "":
            self.load_right_panel()  # Ensure scrollable_frame is initialized first
        else:
            self.clear_chat()
        if not chat_name:
            selected_item = self.contacts_list.selection()
            if not selected_item:
                return
            if self.check_for_pending(selected_item):
                try:
                    self.pending_messages.pop(selected_item[0])
                    self.add_chat_to_left_panel(selected_item[0])
                except Exception as e:
                    print(e)
            chat_name = self.contacts_list.item(selected_item[0], "text").strip("🔴").strip(" ").strip()
        else:
            if self.check_for_pending(chat_name):
                try:
                    self.pending_messages.pop(chat_name)
                    self.add_chat_to_left_panel(chat_name)
                except Exception as e:
                    print(e)
        self.current_chat = chat_name
        self.request_chat_history(chat_name)
        self.chat_label.config(text=chat_name, anchor="w", font=("Ariel", 15))

    def add_chat_to_left_panel(self, chat):
        """Adds a chat to the left panel. Adds a red dot if there’s a new message."""
        if self.check_for_pending(chat) and self.current_chat != chat:
            chat_display = f"🔴 {chat}"
        else:
            chat_display = f"  {chat}"
        try:
            self.contacts_list.item(chat, text=chat_display)
        except Exception:
            self.contacts_list.insert("", "end", iid=chat, text=chat_display)

    def load_right_panel(self):
        """Loads the right panel with chat area, scrollable frame, and message input."""
        self.chat_display = scrolledtext.ScrolledText(self.right_panel, wrap=tk.WORD, state=tk.DISABLED,
                                                      font=("Arial", 12))
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.chat_display.tag_configure("left", justify="left", lmargin1=10, lmargin2=10, foreground="#821025")
        self.chat_display.tag_configure("right", justify="right", rmargin=10, foreground="#121082")
        self.chat_display.tag_configure("date", justify="center", foreground="black", font=("Arial", 10, "italic"))

        self.msg_entry = tk.Entry(self.right_panel, font=("Arial", 12))
        self.msg_entry.pack(padx=10, pady=5, fill=tk.X, side=tk.LEFT, expand=True)
        self.msg_entry.bind("<Return>", self.send_regular_message)

        send_button = tk.Button(self.right_panel, text="Send", command=self.send_regular_message, bg="#25D366",
                                fg="white")
        send_button.pack(padx=10, pady=5, side=tk.LEFT, fill=tk.X)
        ai_button = tk.Button(self.right_panel, text="AI", command=self.send_ai_message, bg="#25D366", fg="white")
        ai_button.pack(padx=5, pady=5, side=tk.LEFT)

    def clear_chat(self):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete("1.0", tk.END)
        self.chat_display.config(state=tk.DISABLED)

    def request_chat_callback(self, chat_name, chat_type, members=None):
        if chat_type == "chat":
            self.request_new_chat(chat_name)
        elif chat_type == "group":
            self.request_new_group(chat_name, members)

    def request_new_group(self, group_name, members: list):
        """Requests creation of new group chat."""
        members.append(self.username)
        try:
            chat_request = create_client_message("create_group", self.username, chat_name=group_name,
                                                 content=",".join(members))
            self.sock.send(
                AES.encrypt_message(json.dumps(chat_request), self.key))  # new protocol implemented
        except Exception as e:
            print(f"[DEBUG] Error during creation of new group chat: {e}")

    def request_new_chat(self, chat_name):
        """Requests creation of new chat."""
        try:
            chat_request = create_client_message("create chat", self.username, chat_name=chat_name)
            self.sock.send(
                AES.encrypt_message(json.dumps(chat_request), self.key))  # new protocol implemented
        except Exception as e:
            print(f"Error during creation of new chat: {e}")

    def request_chat_history(self, chat_name):
        """Requests chat history after ensuring UI is ready."""
        try:
            # self.waiting_for_history = True
            history_request = create_client_message("get_history", self.username, chat_name=chat_name)
            self.sock.send(
                AES.encrypt_message(json.dumps(history_request), self.key))  # new protocol implemented
        except Exception as e:
            print(f"Error during chat history retrieval: {e}")

    def add_and_enter_chat(self, chat_name, chat_type):
        """Adds chat to left panel and enters"""
        if chat_name not in self.chat_dict.keys():
            self.creating_chat = True
            if chat_type == "chat":
                self.chat_dict[chat_name] = "chat"
            elif chat_type == "group":
                self.chat_dict[chat_name] = "group"
            self.add_chat_to_left_panel(chat_name)
        self.enter_chat(chat_name=chat_name)

    def add_text_to_display(self, text, sender=""):
        """Create a message in the scrollable frame."""
        if not hasattr(self, 'chat_display') or not self.chat_display.winfo_exists():
            return
        self.chat_display.config(state=tk.NORMAL)  # Enable editing
        if sender == "You":
            tag = "right"
        elif sender == "date":
            tag = "date"
        else:
            tag = "left"
        self.chat_display.insert(tk.END, f"{sender}: {text}\n", tag)

        self.chat_display.config(state=tk.DISABLED)  # Disable editing
        self.chat_display.yview_moveto(1.0)

    def display_chat_message(self, message):
        if is_datetime(message):
            self.add_text_to_display(message, "date")
        else:
            before, _, after = str(message).partition(":")
            if before == self.username:
                self.add_text_to_display(after.strip("']").strip("['").strip('"'), "You")
            else:
                self.add_text_to_display(after.strip("']").strip("['").strip('"'),
                                         before.strip("']").strip("['").strip('"'))

    # pending
    def check_for_pending(self, chat_name):
        if isinstance(chat_name, str):
            return chat_name in list(self.pending_messages.keys())
        if isinstance(chat_name, tuple):
            return chat_name[0] in list(self.pending_messages.keys())

    # search
    def search_users(self, query):
        search_request = create_client_message("search", self.username, content=query)
        search_message = AES.encrypt_message(json.dumps(search_request), self.key)
        self.sock.send(search_message)

    # receiving messages
    def handle_message_from_server(self, message):
        """Handle messages from server and routes them to correct functions"""
        try:
            if message["type"] == "msg":
                if self.last_conversation_date != self.todays_date:
                    self.display_chat_message(self.todays_date)
                self.display_chat_message(message["content"])  # new protocol implemented
            elif message["type"] == "history":
                history_dict = json.loads(message["content"])  # new protocol implemented
                if history_dict:
                    self.last_conversation_date = list(history_dict.keys())[-1]
                    self.clear_chat()
                    for date in dict(history_dict).keys():
                        self.display_chat_message(date)
                        for msg in list(history_dict[date]):
                            self.display_chat_message(msg)
            elif message["type"] == "pending":
                for key, value in json.loads(message["content"]).items():
                    if self.current_chat == key:
                        self.display_chat_message(value)
                    self.pending_messages.setdefault(key, []).extend(value)
                    for item_id in self.contacts_list.get_children():
                        self.add_chat_to_left_panel(item_id)
            elif message["type"] == "search results":
                Screens.display_results(message["content"].split(","), self.username)
            elif message["type"] == "new chats":
                new_chats = json.loads(message["content"])
                for chat in list(new_chats.keys()):
                    if chat and chat not in self.chat_dict.keys():
                        self.contacts_list.insert("", "end", iid=chat, text=f"  {chat}")
                        self.chat_dict[chat] = new_chats[chat]
            elif message["type"] == "error":
                messagebox.showerror("Error", message["content"])
            elif message["type"] == "chat created":
                messagebox.showinfo("Chat Creation", "chat created successfully")
                chat_name, _, chat_type = str(message["content"]).partition(":")
                self.add_and_enter_chat(chat_name, chat_type)
            elif message["type"] == "chat exists":
                self.enter_chat(chat_name=message["content"])
            else:
                print("Unhandled message format:", message)

            # Ensure we scroll to the bottom
            if hasattr(self, 'canvas'):
                self.canvas.yview_moveto(1.0)
        except Exception as e:
            print(f"Error displaying message: {e}")

    def recv_full_message(self):
        """Receives a full message from server with length prefix."""
        try:
            # Receive exactly 4 bytes
            length_bytes = b''
            while len(length_bytes) < 4:
                chunk = self.sock.recv(4 - len(length_bytes))
                if not chunk:
                    return None
                length_bytes += chunk

            # Get the message length as an integer
            message_length = int.from_bytes(length_bytes, byteorder='big')

            # Receive the actual message
            message_data = b''
            while len(message_data) < message_length:
                chunk = self.sock.recv(min(4096, message_length - len(message_data)))
                if not chunk:
                    return None
                message_data += chunk

            return message_data
        except Exception:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Action failed, please try again"))

    def receive_messages(self):
        """Receives messages from the server and updates the chat display."""
        while self.running:
            try:
                if not self.sock:
                    break
                message_encrypted = self.recv_full_message()
                message = AES.decrypt_message(message_encrypted, self.key)
                if message:
                    # Schedule UI update on the main thread
                    self.master.after(0, lambda msg=message: self.handle_message_from_server(
                        json.loads(msg)))
            except Exception as e:
                if self.running:
                    print(f"Error: {e}")
                break

        # Try to close the socket if still open
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    # sending text messages
    def send_ai_message(self):
        """Sends signal to server for AI response"""
        if self.current_chat != "":
            if self.chat_dict[self.current_chat] == "chat":
                completed_message = create_client_message("chat_ai", self.username, "", self.current_chat)
                threading.Thread(target=self.send_message,
                                 args=(json.dumps(completed_message),)).start()
            elif self.chat_dict[self.current_chat] == "group":
                completed_message = create_client_message("group_ai", self.username, "", self.current_chat)
                threading.Thread(target=self.send_message,
                                 args=(json.dumps(completed_message),)).start()

    def send_regular_message(self):
        """Sends the message typed by the user."""
        message = self.msg_entry.get().strip()
        if message and self.current_chat != "":
            completed_message = create_client_message(self.chat_dict[self.current_chat], self.username,
                                                      content=message,
                                                      chat_name=self.current_chat)
            threading.Thread(target=self.send_message,
                             args=(json.dumps(completed_message),)).start()
            self.msg_entry.delete(0, tk.END)

    def send_message(self, message):
        """Handles sending messages in a separate thread to avoid UI freezing."""
        try:
            if self.sock:
                if self.key:
                    self.sock.send(AES.encrypt_message(json.dumps(message), self.key))
                else:
                    self.sock.send(json.dumps(message).encode())
        except ConnectionResetError:
            self.master.after(0, lambda: messagebox.showerror("Connection Lost",
                                                              "Connection lost. Unable to send message."))
            self.close_socket()
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Failed to send message: {e}"))
            self.close_socket()

    def close_socket(self):
        """Safely closes the socket."""
        if hasattr(self, 'sock') and self.sock:
            try:
                sock = self.sock
                self.sock = None  # Prevent other threads from using it
                sock.close()
            except:
                pass

    def on_closing(self):
        """Handles cleanup when the window is closed."""
        self.running = False
        self.close_socket()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    client = Client(root)
    root.protocol("WM_DELETE_WINDOW", client.on_closing)
    root.mainloop()
