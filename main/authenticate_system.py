import hashlib
import re
import sqlite3
import logging
import getpass
from tkinter import messagebox
import random
import string

class AuthenticationSystem():
    """
    Implementation of the AthenticationSystem using hashing
    """
    def __init__(self, db_path="credentials.db"):
        # storing the data in a database
        self.db_path = db_path
        self._create_table_if_not_exists()

    def generate_otp(self):
        # Generate a random 6-digit OTP
        return ''.join(random.choices(string.digits, k=6))

    def _setup_logging(self):
        logging.basicConfig(filename="authentication.log",
                            level=logging.INFO,
                            format="%(asctime)s - %(levelname)s - %(message)s")
        

    def _create_table_if_not_exists(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
        """
            CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            hashed_password TEXT
            )
        """
        )
        conn.commit()
        conn.close()

    def _hash_password(self, password):
        """
        Hash the given password using SHA-256.

        Parameters:
            password (str): The password to be hashed.

        Returns:
            str: The hashed password.
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username, password):
        """
        Register a user by storing the hashed password for the given username

        Args:
            username (str):  The username of the user
            password (str): The password to be hashed and stored

        Return:
            None
        """
        while not True:
            self.check_password_strength(password)

        hashed_password = self._hash_password(password)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
        """
            INSERT INTO users (username, password, hashed_password)
            VALUES (?, ?, ?)
        """, (username, password, hashed_password)
        )
        conn.commit()
        conn.close()

        # hashed_password = self._hash_password(password)     # generating the hash
        # self.user_credentials[username] = hashed_password   # storing the hash

    def check_password_strength(self, password):
        """ 
        Check the strengthof the password based on the length and complexity criteria
        
        Args:
            password (str): The password to be checked for strength
        
        Returns:
           bool : A indicating the password strength
        """
        passed = True
        length_criteria = 8
        complexity_criteria = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]'

        if len(password) < length_criteria or not re.match(complexity_criteria, password):
            print("Password must be minimum of 8 characters and must at least contain one special character and one digit")
            return not passed

        return passed


    def authenticate_user(self, username, password):
        """
        Authenticate a user by comparing the entered password with the stored hased password

        Args:
            username (str): The password of the user
            password (_type_): The password to be checked for authentication

        Returns:
            bool: True if authentication is succeessful, False if authentication fails
        """
        while not True:
            self.check_password_strength(password)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()        

        if result:
            stored_hashed_password = result[0]
            entered_password_hash = self._hash_password(password)
            if entered_password_hash == stored_hashed_password:
                logging.info(f"Authentication succesful for user: {username}")
                return True
            else:
                logging.warning(f"Authentication failed for user: {username}")
                return False
        else:
            logging.warning(f"User not found: {username}")
        

        # stored_passsword_hash = self.user_credentials.get(username)      # getting the stored hash
        # if stored_passsword_hash:
        #     entered_password_hash = self._hash_password(password)
        #     return entered_password_hash == stored_passsword_hash
        # else:
        #     False

    
    def update_password(self, username, new_password):
        """ 
        Updates the users password.

        Args:
            username (str): name of the user
            new_password (str): new password to update the old one
        
        Return:
            None
        """
        self.check_password_strength(new_password)
        hashed_password = self._hash_password(new_password)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor() 
        cursor.excute("UPDATE users SET hashed_password = ? WHERE username = ?", (hashed_password, username,))
        conn.commit()
        conn.close()

    def remove_user(self, username):
        """ 
        Removes a user's credentials from the database
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor() 
        cursor.excute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()

    # Function to handle registration
    def register_user_gui(self, username, password):
        # Generate an OTP and store it for the user
        otp = self.generate_otp()
        self.user_otp[username] = otp

        self.register_user(username, password)
        messagebox.showinfo("Registration", "User registered successfully.")

    # Function to handle authentication
    def authenticate_user_gui(self):
        username = self.username_entry.get()
        password = getpass.getpass("Enter password: ")

        # Check if the user exists and get stored OTP
        if self.user_exists(username):
            stored_otp = self.user_otp.get(username)
            entered_otp = input("Enter OTP: ")

            stored_password_hash = self._hash_password(password)
            entered_password_hash = self._hash_password(password + stored_otp)

            if entered_password_hash == stored_password_hash and entered_otp == stored_otp:
                logging.info(f'Authentication successful for user: {username}')
                messagebox.showinfo("Authentication", "Authentication successful!")
            else:
                logging.warning(f'Authentication failed for user: {username}')
                messagebox.showerror("Authentication", "Authentication failed.")
        else:
            logging.warning(f'User not found: {username}')
            messagebox.showerror("Authentication", "User not found.")

    # Function to handle password recovery simulation
    def reset_password_gui(self):
        username = self.username_entry.get()
        
        if self.user_exists(username):
            new_password = getpass.getpass("Enter a new password: ")
            self.update_password(username, new_password)
            messagebox.showinfo("Password Reset", "Password reset successfully.")
        else:
            messagebox.showerror("Password Reset", "User not found. Invalid username.")

    # Function to check if user exists
    def user_exists(self, username):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        return result is not None