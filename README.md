# Masai-School-Project
Project Name: Secure Banking System
Language Used: Python
Tools and Libraries:

hashlib: For password hashing (PBKDF2-HMAC with SHA-256)
os: For file handling and generating salt for password hashing
re: For validation of Aadhaar, PAN, and email using regular expressions
json: For storing user data in JSON format
datetime: For timestamping transactions and logs
File Handling: To create persistent data storage using .txt and .json files
Project Overview:
The Secure Banking System is a Python-based application that simulates a secure banking environment, allowing users to create bank accounts, deposit and withdraw money, and ensure data security using hashed passwords. The system features functionalities for both employees and users:

Account Creation: Allows users to create a bank account by providing personal details (name, Aadhaar, PAN, email, etc.).
Transaction Logs: Keeps track of each transaction (deposit/withdrawal) with timestamp, account number, type, amount, and updated balance.
Password Security: Uses hashing techniques (PBKDF2 with SHA-256) to store passwords securely.
Employee Actions: Allows employees to create user accounts and log their actions.
Validation: Validates Aadhaar, PAN, and email input from the user during account creation.
Detailed Explanation of the Code:
1. Importing Libraries:

import hashlib
import os
import re
import json
from datetime import datetime
hashlib: Used for password hashing, a crucial part of this system's security.
os: Helps with file creation and handling random data (like salt for password hashing).
re: Used for validating user inputs like Aadhaar, PAN, and email.
json: Enables reading from and writing data to a JSON file, where user details are stored.
datetime: Captures and formats timestamps for logging transactions.
2. File Initialization:

USER_DATA_FILE = 'users.json'
TRANSACTION_LOG_FILE = 'transactions.txt'
EMPLOYEE_LOG_FILE = 'employee_log.txt'
These variables specify the file names where user data, transaction logs, and employee actions are stored. Files are created automatically if they don't already exist when the program runs.

3. Function to Initialize Files:

def initialize_files():
    if not os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f)
    if not os.path.exists(TRANSACTION_LOG_FILE):
        open(TRANSACTION_LOG_FILE, 'a', encoding='utf-8').close()
    if not os.path.exists(EMPLOYEE_LOG_FILE):
        open(EMPLOYEE_LOG_FILE, 'a', encoding='utf-8').close()
This function checks if the necessary files exist, and if not, it creates them:

users.json: Stores user information such as account details, hashed passwords, and balance.
transactions.txt: Keeps a log of all financial transactions.
employee_log.txt: Logs the actions performed by employees.
4. Password Hashing Functions:

def hash_password(password):
    salt = os.urandom(16)
    hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + hashed_pw

def verify_password(stored_password, provided_password):
    salt = stored_password[:16]
    stored_hash = stored_password[16:]
    provided_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return provided_hash == stored_hash
hash_password: This function generates a salt (random 16 bytes), and then applies PBKDF2-HMAC-SHA256 to hash the password. The salt is stored along with the hash to verify the password later.
verify_password: This function compares the hash of the entered password with the stored hash by extracting the salt from the stored password.
5. Validation Functions:

def validate_aadhaar(aadhaar):
    return re.fullmatch(r'\d{12}', aadhaar) is not None

def validate_pan(pan):
    return re.fullmatch(r'[A-Z]{5}\d{4}[A-Z]', pan) is not None

def validate_email(email):
    return re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email) is not None
These functions use regular expressions to ensure that user inputs for Aadhaar, PAN, and email are in the correct formats:

Aadhaar: 12 digits.
PAN: Format like ABCDE1234F.
Email: Standard email format like example@example.com.
6. User Data Management:

def load_user_data():
    with open(USER_DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_user_data(data):
    with open(USER_DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
load_user_data: Reads the users.json file to load user data into memory.
save_user_data: Writes the current user data back to the users.json file, saving any changes (such as after a deposit or account creation).
7. Logging Transactions and Employee Actions:

def log_transaction(account_number, transaction_type, amount, balance):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(TRANSACTION_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{timestamp} - Account: {account_number}, Type: {transaction_type}, Amount: ₹{amount}, Balance: ₹{balance}\n")
    return timestamp

def log_employee_action(employee_name, action):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(EMPLOYEE_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{timestamp} - {employee_name} performed action: {action}\n")
log_transaction: Logs each transaction (deposit or withdrawal) with details like account number, transaction type, amount, and balance.
log_employee_action: Logs actions performed by employees, such as account creation.
8. Account Management Functions:
create_account: This function allows a user to create an account. It collects details (such as name, Aadhaar, PAN, email) and stores them in the users.json file, along with the account number and balance. It also includes validation for Aadhaar, PAN, email, and the password.
deposit and withdraw: These functions allow users to deposit or withdraw money from their account. They also log the transactions.
9. User and Employee Login:
user_login: Verifies user login credentials and lets the user perform banking actions such as deposits and withdrawals.
employee_login: Employees can log in and perform actions like creating user accounts.
10. Main Program:

def main():
    initialize_files()
    while True:
        print("\nWelcome to the Secure Banking System")
        print("1. Create Account (Self Registration)\n2. User Login\n3. Employee Login\n4. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            create_account()  # Self-registration for the user
        elif choice == "2":
            user_login()
        elif choice == "3":
            employee_login()
        elif choice == "4":
            print("Thank you for using the Secure Banking System. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")
The main function initializes files and provides the user with options to create an account, log in as a user, log in as an employee, or exit the system. It repeatedly prompts the user for input until they choose to exit.

Conclusion:
This Secure Banking System is a functional and secure banking application developed using Python. The system ensures user data protection with password hashing and provides essential banking operations such as account creation, deposits, withdrawals, and transaction logging. Additionally, it offers an employee interface for managing accounts and activities. This project covers key concepts in file handling, password security, input validation, and transaction management.






