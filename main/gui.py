import tkinter as tk
from tkinter import messagebox
from authenticate_system import AuthenticationSystem

def gui():
    root = tk.Tk()
    root.title("User Authentication")
    root.geometry("500x300")
    
    auth_system = AuthenticationSystem()
    # username widgets
    tk.Label(root, text="Username", width=50).pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    # password widgets
    tk.Label(root, text="Password", width=50).pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    username = username_entry.get()
    password = password_entry.get()

    register_button = tk.Button(root, text="Register", command=auth_system.register_user_gui(username, password))
    register_button.pack()

    authenticate_button = tk.Button(root, text="Authenticate", command=auth_system.authenticate_user_gui(username, password))
    authenticate_button.pack()

    root.mainloop()

if __name__ == "__main__":
    gui()