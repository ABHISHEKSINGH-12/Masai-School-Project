import hashlib
import os
import re
import json
from datetime import datetime

# Paths for persistent data
USER_DATA_FILE = 'users.json'
TRANSACTION_LOG_FILE = 'transactions.txt'
EMPLOYEE_LOG_FILE = 'employee_log.txt'

# Initialize files if they do not exist
def initialize_files():
    if not os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f)
    if not os.path.exists(TRANSACTION_LOG_FILE):
        open(TRANSACTION_LOG_FILE, 'a', encoding='utf-8').close()
    if not os.path.exists(EMPLOYEE_LOG_FILE):
        open(EMPLOYEE_LOG_FILE, 'a', encoding='utf-8').close()

# Utility functions
def hash_password(password):
    salt = os.urandom(16)
    hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + hashed_pw

def verify_password(stored_password, provided_password):
    salt = stored_password[:16]
    stored_hash = stored_password[16:]
    provided_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return provided_hash == stored_hash

def validate_aadhaar(aadhaar):
    return re.fullmatch(r'\d{12}', aadhaar) is not None

def validate_pan(pan):
    return re.fullmatch(r'[A-Z]{5}\d{4}[A-Z]', pan) is not None

def validate_email(email):
    return re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email) is not None

def load_user_data():
    with open(USER_DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_user_data(data):
    with open(USER_DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def log_transaction(account_number, transaction_type, amount, balance):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(TRANSACTION_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{timestamp} - Account: {account_number}, Type: {transaction_type}, Amount: ₹{amount}, Balance: ₹{balance}\n")
    return timestamp

def log_employee_action(employee_name, action):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(EMPLOYEE_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{timestamp} - {employee_name} performed action: {action}\n")

# Account Management Functions
def create_account(employee_name=None):
    print("--- Account Creation ---")
    print("Select Title:")
    print("1. Mr.\n2. Miss\n3. Mrs.\n4. Dr.")
    title_choice = input("Enter your choice: ")
    titles = {"1": "Mr.", "2": "Miss", "3": "Mrs.", "4": "Dr."}
    if title_choice not in titles:
        print("Invalid choice.")
        return
    title = titles[title_choice]

    first_name = input("Enter First Name: ")
    middle_name = input("Enter Middle Name (optional): ")
    last_name = input("Enter Last Name: ")

    aadhaar = input("Enter Aadhaar Number (12 digits): ")
    if not validate_aadhaar(aadhaar):
        print("Invalid Aadhaar format.")
        return

    pan = input("Enter PAN Number (10 characters): ")
    if not validate_pan(pan):
        print("Invalid PAN format.")
        return

    email = input("Enter Email (example@example.com): ")
    if not validate_email(email):
        print("Invalid email format.")
        return

    account_type_choice = input("Account Type (1. Savings / 2. Current):\nEnter your choice: ")
    account_types = {"1": "Savings", "2": "Current"}
    if account_type_choice not in account_types:
        print("Invalid choice.")
        return
    account_type = account_types[account_type_choice]

    initial_deposit = input("Enter Initial Deposit (minimum ₹500): ")
    try:
        initial_deposit = float(initial_deposit)
        if initial_deposit < 500:
            print("Initial deposit must be at least ₹500.")
            return
    except ValueError:
        print("Invalid amount.")
        return

    password = input("Set Your Password: ")
    confirm_password = input("Confirm Your Password: ")
    if password != confirm_password:
        print("Passwords do not match.")
        return

    if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password) or not re.search(r'[!@#$%^&*]', password):
        print("Password must be at least 8 characters long and include letters, numbers, and special symbols.")
        return

    user_data = load_user_data()
    account_number = str(10001 + len(user_data))

    user_data[account_number] = {
        "title": title,
        "first_name": first_name,
        "middle_name": middle_name,
        "last_name": last_name,
        "aadhaar": aadhaar,
        "pan": pan,
        "email": email,
        "account_type": account_type,
        "balance": initial_deposit,
        "password": hash_password(password).hex(),
        "created_at": datetime.now().strftime("%d %m %Y %H:%M"),
        "created_by": employee_name if employee_name else "User"
    }

    save_user_data(user_data)

    print("\nAccount created successfully!")
    print(f"Your Account Number is: {account_number}")
    print(f"Account created on: {user_data[account_number]['created_at']} by {user_data[account_number]['created_by']}")
    print("Save it for future reference.")
    
    if employee_name:
        log_employee_action(employee_name, "Created account for " + first_name)

def deposit(account_number):
    try:
        user_data = load_user_data()
        if account_number not in user_data:
            print("Account not found.")
            return

        amount = input("Enter amount to deposit: ")
        try:
            amount = float(amount)
            if amount <= 0:
                print("Deposit amount must be positive.")
                return
        except ValueError:
            print("Invalid amount.")
            return

        user_data[account_number]["balance"] += amount
        save_user_data(user_data)
        timestamp = log_transaction(account_number, "Deposit", amount, user_data[account_number]["balance"])
        print(f"Deposit successful at {timestamp}! Current balance: ₹{user_data[account_number]['balance']}")
    except Exception as e:
        print(f"An error occurred: {e}")

def withdraw(account_number):
    user_data = load_user_data()
    if account_number not in user_data:
        print("Account not found.")
        return

    amount = input("Enter amount to withdraw: ")
    try:
        amount = float(amount)
        if amount <= 0:
            print("Withdrawal amount must be positive.")
            return
        if amount > user_data[account_number]["balance"]:
            print("Insufficient balance.")
            return
    except ValueError:
        print("Invalid amount.")
        return

    user_data[account_number]["balance"] -= amount
    save_user_data(user_data)
    timestamp = log_transaction(account_number, "Withdrawal", amount, user_data[account_number]["balance"])
    print(f"Withdrawal successful at {timestamp}! Current balance: ₹{user_data[account_number]['balance']}")

def user_login():
    print("--- User Login ---")
    account_number = input("Enter Account Number: ")
    password = input("Enter Password: ")

    user_data = load_user_data()
    if account_number not in user_data:
        print("Invalid Account Number or Password.")
        return

    stored_password = bytes.fromhex(user_data[account_number]["password"])
    if not verify_password(stored_password, password):
        print("Invalid Account Number or Password.")
        return

    print("Login Successful!")

    while True:
        print("\n1. Deposit Money\n2. Withdraw Money\n3. Logout")
        choice = input("Enter your choice: ")

        if choice == "1":
            deposit(account_number)
        elif choice == "2":
            withdraw(account_number)
        elif choice == "3":
            print("Logging out...")
            break
        else:
            print("Invalid choice. Please try again.")

def employee_login():
    print("--- Employee Login ---")
    username = input("Enter Employee Username: ")
    password = input("Enter Employee Password: ")

    if username == "employee1" and password == "password1":
        print(f"{username} Login Successful!")
        create_account(employee_name=username)
    else:
        print("Invalid Employee Credentials.")

# Main Program
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

if __name__ == "__main__":
    main()
