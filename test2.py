import sqlite3
import tkinter as tk
from tkinter import messagebox

# Connect to the SQLite3 database
conn = sqlite3.connect('user_database.db')
c = conn.cursor()

# Create users table if it does not exist
c.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                name TEXT,
                email TEXT,
                role TEXT)''')
conn.commit()

# Ensure the admin user exists
def initialize_admin_user():
    admin_username = 'admin'
    admin_password = 'adminpassword'
    admin_name = 'Admin User'
    admin_email = 'admin@example.com'
    admin_role = 'admin'

    c.execute("SELECT * FROM users WHERE username=?", (admin_username,))
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password, name, email, role) VALUES (?, ?, ?, ?, ?)",
                  (admin_username, admin_password, admin_name, admin_email, admin_role))
        conn.commit()
        print("Admin user initialized.")
    else:
        print("Admin user already exists.")

# Call the function to ensure admin user is initialized
initialize_admin_user()

def view_user_info(username):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user_info = c.fetchone()
    if user_info:
        user_info_text = f"User Information:\nUsername: {user_info[0]}\nName: {user_info[2]}\nEmail: {user_info[3]}\nRole: {user_info[4]}"
        messagebox.showinfo("User Information", user_info_text)
    else:
        messagebox.showerror("Error", "User not found.")

def register_user(admin_window):
    def on_register():
        new_username = username_entry.get()
        new_password = password_entry.get()
        name = name_entry.get()
        email = email_entry.get()
        role = role_entry.get()

        c.execute("SELECT * FROM users WHERE username=?", (new_username,))
        if c.fetchone():
            messagebox.showerror("Error", "Username already exists. Please choose a different username.")
        else:
            c.execute("INSERT INTO users (username, password, name, email, role) VALUES (?, ?, ?, ?, ?)",
                      (new_username, new_password, name, email, role))
            conn.commit()
            messagebox.showinfo("Success", "Registration successful! You can now log in with your new credentials.")
            register_window.destroy()

    register_window = tk.Toplevel(admin_window)
    register_window.title("Register New User")

    username_label = tk.Label(register_window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(register_window)
    username_entry.pack()

    password_label = tk.Label(register_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(register_window, show="*")
    password_entry.pack()

    name_label = tk.Label(register_window, text="Name:")
    name_label.pack()
    name_entry = tk.Entry(register_window)
    name_entry.pack()

    email_label = tk.Label(register_window, text="Email:")
    email_label.pack()
    email_entry = tk.Entry(register_window)
    email_entry.pack()

    role_label = tk.Label(register_window, text="Role (admin/user):")
    role_label.pack()
    role_entry = tk.Entry(register_window)
    role_entry.pack()

    register_button = tk.Button(register_window, text="Register", command=on_register)
    register_button.pack()

def admin_menu(username):
    admin_window = tk.Tk()
    admin_window.title("Admin Menu")

    def view_user_info_gui():
        view_username = tk.simpledialog.askstring("View User Information", "Enter the username you want to view:")
        if view_username:
            view_user_info(view_username)

    view_info_button = tk.Button(admin_window, text="View User Information", command=view_user_info_gui)
    view_info_button.pack()

    register_button = tk.Button(admin_window, text="Register New User", command=lambda: register_user(admin_window))
    register_button.pack()

    logout_button = tk.Button(admin_window, text="Logout", command=admin_window.destroy)
    logout_button.pack()

    admin_window.mainloop()

def login_gui():
    window = tk.Tk()
    window.title("User Login System")

    def on_login():
        username = username_entry.get()
        password = password_entry.get()

        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()

        if user:
            role = user[4]
            messagebox.showinfo("Login Successful", "Welcome, {}!".format(username))
            window.destroy()
            if role == 'admin':
                admin_menu(username)
            else:
                messagebox.showinfo("Login Successful", "Welcome, {}!".format(username))
                # Add any other user-specific functionality here
        else:
            messagebox.showerror("Login Failed", "Invalid username or password. Please try again.")

    # GUI components
    username_label = tk.Label(window, text="Username:")
    username_label.pack()
    username_entry = tk.Entry(window)
    username_entry.pack()

    password_label = tk.Label(window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(window, show="*")
    password_entry.pack()

    login_button = tk.Button(window, text="Login", command=on_login)
    login_button.pack()

    window.mainloop()

if __name__ == "__main__":
    print("User Login System")
    while True:
        choice = input("Choose an option (login/exit): ").lower()

        if choice == "login":
            login_gui()  # Launch the GUI for login
            # Additional logic can be added here after the GUI is closed
        elif choice == "exit":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please choose 'login' or 'exit'.")
