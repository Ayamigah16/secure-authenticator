# Authentication System
## Overview
This project implements a simple authentication system in Python. The system allows users to register, authenticate using passwords, tokens, or OTPs, reset passwords, and implements account locking after a certain number of unsuccessful login attempts.

## Features
**1. User Registration:**

- Users can register by providing a username, password, and an OTP (One-Time Password).

**2. Authentication:**

- Users can authenticate using one of the following methods:
    - Password authentication.
    - Token authentication.
- OTP (One-Time Password) is used in combination with passwords for added security.

**3. Password Reset:**

- Users can reset their passwords.

**4. Account Locking:**

- After a specified number of unsuccessful login attempts, the user's account is temporarily locked.

**5. Token-Based Authentication:**

- Users can authenticate using tokens in addition to passwords and OTPs.

## Setup and Usage
**1. Clone the Repository:**

```
    git clone <repository_url>
    cd authentication-system
```

**2. Install Dependencies:**
- This project uses standard Python libraries and does not require additional installations.

**3. Run the Program:**
```
    python main.py
```
- Follow the on-screen instructions to register and authenticate users.

**4. Registration:**

- Enter a username, password, and OTP during registration.

**5. Authentication:**

- Choose 'P' for password authentication or 'T' for token authentication.
- Enter the requested details based on the chosen authentication method.

**6. Password Reset:**
- Use the 'Reset Password' button in the GUI.


## Example Usage
```
    Register a user:

    Username: user1
    Password: password123
    OTP: 123456
    Authenticate using password:

    Username: user1
    Password: password123
    OTP: 123456
    Authenticate using token:

    Username: user1
    Token: [Generated during registration]
```