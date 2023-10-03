import hashlib
import re

class AuthenticationSystem():
    """
    Implementation of the AthenticationSystem using hashing
    """

    def __init__(self):
        # a data structure to store user credentials
        self.user_credentials = {}

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
        hashed_password = self._hash_password(password)     # generating the hash
        self.user_credentials[username] = hashed_password   # storing the hash

    def check_password_strength(self, password):
        """ 
        Check the strengthof the password based on the length and complexity criteria
        
        Args:
            password (str): The password to be checked for strength
        
        Returns:
            str: A indicating the password strength
        """
        passed = True
        length_criteria = 8
        complexity_criteria = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]'

        if len(password) < length_criteria:
            print("Password is too short.\nIt must be at least  8 characters long")
            return not passed

        if not re.match(complexity_criteria, password):
            "Password is not too complex enough.\nIt must at least contain one special character and one digit."
            return not passed

        return passed


    def authenticate_usesr(self, username, password):
        """
        Authenticate a user by comparing the entered password with the stored hased password

        Args:
            username (str): The password of the user
            password (_type_): The password to be checked for authentication

        Returns:
            bool: True if authentication is succeessful, False if authentication fails
        """
        stored_passsword_hash = self.user_credentials.get(username)      # getting the stored hash
        if stored_passsword_hash:
            entered_password_hash = self._hash_password(password)
            return entered_password_hash == stored_passsword_hash
        else:
            False
    