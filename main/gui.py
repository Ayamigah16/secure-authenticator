import tkinter as tk
from tkinter import messagebox
from authenticate_system import AuthenticationSystem

def gui():
    root = tk.Tk()
    root.title("User Authentication")
    root.geometry("500x300")
    
    # username widgets
    tk.Label(root, text="Username", width=50).pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    # password widgets
    tk.Label(root, text="Password", width=50).pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    # getting inputs from the gui
    username = username_entry.get()
    password = password_entry.get()

    # authentication object
    auth_system = AuthenticationSystem(username=username,password=password)

    # creating register button
    register_button = tk.Button(root, text="Register", command=auth_system.register_user_gui())
    register_button.pack()

    # creating authentication button
    authenticate_button = tk.Button(root, text="Authenticate", command=auth_system.authenticate_user_gui())
    authenticate_button.pack()

    # Create a button for password reset
    reset_password_button = tk.Button(root, text="Reset Password", command=auth_system.reset_password_gui)
    reset_password_button.pack()

    root.mainloop()

if __name__ == "__main__":
    gui()