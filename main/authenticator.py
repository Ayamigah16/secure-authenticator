# importing class
from authenticate_system import AuthenticationSystem

if __name__ == "__main__":
    auth_system = AuthenticationSystem()

    # register user
    auth_system.register_user("user1", "password")

    # authenticate a user
    entered_username = input("Enter username: ")
    entered_password = input("Enter password: ")

    if auth_system.authenticate_usesr(entered_username, entered_password):
        print("Authentication successful!")
    else:
        print("Authentication failed")
