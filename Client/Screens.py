import tkinter as tk
from tkinter import messagebox


# signup window
def sign_up(root, entry_username, entry_password, entry_confirm_password, callback=None):
    username = entry_username.get()
    password = entry_password.get()
    confirm_password = entry_confirm_password.get()

    if not username or not password or not confirm_password:
        messagebox.showerror("Error", "All {*} fields are required!")
        return

    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match!")
        return

    callback(username, password)
    root.destroy()


def create_signup_window(callback=None):
    root = tk.Tk()
    root.title("Sign Up")
    root.geometry("300x400")
    root.config(bg="#415a77")

    tk.Label(root, text="Sign Up", font=("Arial", 18, "bold"), bg="#415a77", fg="white").pack(pady=10)
    tk.Label(root, text="*Username", bg="#415a77", fg="white").pack(pady=5)
    entry_username = tk.Entry(root)
    entry_username.pack(pady=5)

    tk.Label(root, text="*Password", bg="#415a77", fg="white").pack(pady=5)
    entry_password = tk.Entry(root, show="*")
    entry_password.pack(pady=5)

    tk.Label(root, text="*Confirm Password", bg="#415a77", fg="white").pack(pady=5)
    entry_confirm_password = tk.Entry(root, show="*")
    entry_confirm_password.pack(pady=5)

    tk.Button(root, text="Sign Up",
              command=lambda: sign_up(root, entry_username, entry_password, entry_confirm_password, callback, ),
              bg="#d41735",
              fg="white", width=15).pack(pady=20)

    root.mainloop()


# new group window
def create_group_creation_window(all_users, on_create):
    window = tk.Toplevel()
    window.title("Create Group Chat")
    window.geometry("300x400")
    window.config(bg="#415a77")

    tk.Label(window, text="Group Name:", bg="#415a77", font=("Arial", 12)).pack(pady=(10, 2))
    group_entry = tk.Entry(window, width=30)
    group_entry.pack(pady=(0, 10))

    tk.Label(window, text="Select Users:", bg="#415a77", font=("Arial", 12)).pack()
    user_listbox = tk.Listbox(window, selectmode=tk.MULTIPLE, width=30, height=10)
    user_listbox.pack(pady=5)

    for user in all_users:
        user_listbox.insert(tk.END, user)

    button_frame = tk.Frame(window, bg="#415a77")
    button_frame.pack(pady=15)

    def create_group():
        name = group_entry.get().strip()
        selected_indices = user_listbox.curselection()
        selected_users = [user_listbox.get(i) for i in selected_indices]

        if not name:
            messagebox.showwarning("Missing Name", "Please enter a group name.")
            return
        if not selected_users:
            messagebox.showwarning("No Users", "Please select at least one user.")
            return

        on_create(name, "group", selected_users)
        window.destroy()

    def cancel():
        window.destroy()

    tk.Button(button_frame, text="Create", command=create_group, bg="#25D366", fg="white").pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Cancel", command=cancel, bg="#FF3B30", fg="white").pack(side=tk.LEFT, padx=5)


# search window
def display_results(users, username):
    result_listbox.delete(0, tk.END)
    for user in users:
        if user != username:
            result_listbox.insert(tk.END, user)

    if users and not result_listbox.winfo_ismapped():
        result_listbox.pack(pady=10)


def create_search_ui(callback=None, click_function=None):
    global root, result_listbox

    def call_search_action():
        query = search_entry.get().lower()
        callback(query)
        print("call back function called")

    def global_click(event):
        clicked_widget = event.widget
        widgets_to_ignore = (result_listbox, search_entry, search_button)

        if clicked_widget not in widgets_to_ignore and not any(
                w in str(clicked_widget) for w in map(str, widgets_to_ignore)):
            if result_listbox.winfo_ismapped():
                result_listbox.pack_forget()

    def on_result_click(event):
        selection = result_listbox.curselection()
        if selection:
            selected_user = result_listbox.get(selection[0])
            click_function(selected_user, "chat")
            print(f"Clicked on: {selected_user}")
            result_listbox.pack_forget()

    root = tk.Tk()
    root.title("Search Users")
    root.geometry("300x300")
    root.config(bg="#415a77")

    search_frame = tk.Frame(root, bg="#415a77")
    search_frame.pack(pady=10)

    tk.Label(search_frame, text="Search Users!", bg="#415a77").pack(side=tk.LEFT, padx=(0, 5))

    search_entry = tk.Entry(search_frame, width=20)
    search_entry.pack(side=tk.LEFT, padx=(0, 5))

    search_button = tk.Button(search_frame, text="🔍", command=call_search_action, bg="#d41735", fg="white")
    search_button.pack(side=tk.LEFT)

    tk.Label(root, text="Click on User to Add as a Friend!", bg="#415a77").pack(padx=(0, 5))
    result_listbox = tk.Listbox(root, width=35, height=8)
    result_listbox.bind("<<ListboxSelect>>", on_result_click)

    root.bind("<Button-1>", global_click)

    root.mainloop()
