# importing class
from authenticate_system import AuthenticationSystem

def main():
    auth_system = AuthenticationSystem()

    # register user
    auth_system.register_user("user1", "password")

    # authenticate a user
    entered_username = input("Enter username: ")
    entered_password = input("Enter password: ")

    strength_result = auth_system.check_password_strength(entered_password)
    print(strength_result)

    if auth_system.authenticate_user(entered_username, entered_password):
        print("Authentication successful!")
    else:
        print("Authentication failed")



if __name__ == "__main__":
    main()