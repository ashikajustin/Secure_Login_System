# Secure Login System

A secure web-based authentication system developed using Python and Flask.

## Features

- User registration
- User login
- Secure password hashing using bcrypt
- Basic username and password validation
- Protection against SQL injection using parameterized SQL queries
- Session management
- Logout functionality
- SQLite database
- Simple and user-friendly web interface

## Technologies Used

- Python
- Flask
- SQLite
- bcrypt
- HTML
- CSS

## Security Features

### Password Hashing

Passwords are never stored as plain text. The application uses bcrypt to securely hash passwords before storing them in the database.

### SQL Injection Protection

Parameterized SQL queries are used when communicating with the SQLite database.

### Input Validation

The application validates usernames and requires passwords to contain at least 8 characters.

### Session Management

Flask sessions are used to maintain authenticated users. The logout function clears the session.

## Project Structure

```text
Secure_Login_System/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
└── users.db