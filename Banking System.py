import tkinter as tk
from tkinter import messagebox
import bcrypt
import time
import random
import smtplib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import re
import logging

# Logging setup for security auditing
logging.basicConfig(filename="secure_chat_system.log", level=logging.INFO)

# Account class with enhanced security features
class Account:
    def __init__(self, name, accnum, pword, email, balance=0):
        self.failed_attempts = 0
        self.lock_time = None
        self.name = name
        self.accnum = accnum
        self.pword = self.hash_password(pword)
        self.email = email  # Add email attribute
        self.balance = balance

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt)

    def check_password(self, input_password):
        return bcrypt.checkpw(input_password.encode('utf-8'), self.pword)

    def close_account(self, name, accnum, pword):
        if self.name == name and self.accnum == accnum and self.check_password(pword):
            self.hasaccount = False
            return "Account closed successfully."
        return "Invalid credentials, unable to close account."

    def check_balance(self, accnum, pword):
        if self.accnum == accnum and self.check_password(pword):
            return f"Your balance is {self.balance:.2f}"
        return "Invalid credentials, cannot show balance."

    def deposit(self, accnum, balance):
        if self.accnum == accnum:
            if balance > 0:
                self.balance += balance
                logging.info(f"Deposit of {balance} successful. New balance: {self.balance}")
                return f"Amount deposited successfully. New balance: {self.balance:.2f}"
            return "Cannot deposit this amount."
        return "Invalid credentials."

    def withdraw(self, accnum, balance, pword):
        if self.accnum == accnum and self.check_password(pword):
            if balance > 0 and self.balance >= balance:
                self.balance -= balance
                logging.info(f"Withdrawal of {balance} successful. Remaining balance: {self.balance}")
                return f"Amount withdrawn successfully. Remaining balance: {self.balance:.2f}"
            return "Cannot withdraw this amount."
        return "Invalid credentials."

    def display_info(self, accnum, pword):
        if self.accnum == accnum and self.check_password(pword):
            return f"Name: {self.name}\nAccount No: {self.accnum}\nAvailable Balance: {self.balance:.2f}"
        return "Enter correct details to see information."

    def check_account_lock(self):
        if self.failed_attempts >= 3:
            if time.time() - self.lock_time < 900:  # Lock for 15 minutes
                return "Account is locked. Try again later."
            else:
                self.failed_attempts = 0  # Reset after lock period
                return None
        return None

    def authenticate(self, pword):
        lock_message = self.check_account_lock()
        if lock_message:
            return lock_message

        if self.check_password(pword):
            self.failed_attempts = 0  # Reset after successful login
            return "Login successful!"
        else:
            self.failed_attempts += 1
            if self.failed_attempts == 3:
                self.lock_time = time.time()
            return "Invalid credentials. Try again."

# Dictionary to store accounts
users = {}

# Send OTP for 2FA
def send_otp(email):
    otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login('your_email@example.com', 'your_password')  # Replace with actual email and password
        message = f"Your one-time password is {otp}"
        server.sendmail('your_email@example.com', email, message)
    return otp

# Encrypt sensitive data like account balance
def encrypt_data(data, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct  # Return both IV and ciphertext

def decrypt_data(enc_data, key):
    iv = base64.b64decode(enc_data[:24])  # IV is stored as first 24 chars
    ct = base64.b64decode(enc_data[24:])
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return decrypted_data

# Input validation functions
def validate_account_number(accnum):
    if not isinstance(accnum, int):
        raise ValueError("Account number must be a number")
    return True

def validate_password(pword):
    if len(pword) < 8 or not re.search(r"\d", pword) or not re.search(r"\W", pword):
        raise ValueError("Password must be at least 8 characters, contain a number, and a special character.")
    return True

# GUI Application
def create_account():
    def submit():
        name = name_entry.get()
        accnum = accnum_entry.get()
        pword = pword_entry.get()
        email = email_entry.get()  # Get email from the entry

        # Account number should be an integer
        try:
            accnum = int(accnum)
        except ValueError:
            messagebox.showerror("Error", "Account number must be a number!")
            return

        try:
            validate_password(pword)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return

        if accnum in users:
            messagebox.showerror("Error", "Account number already exists!")
        else:
            users[accnum] = Account(name, accnum, pword, email)
            messagebox.showinfo("Success", "Account created successfully!")
            create_window.destroy()

    create_window = tk.Toplevel(root)
    create_window.title("Create Account")
    create_window.geometry("500x320")

    tk.Label(create_window, text="Name:").pack()
    name_entry = tk.Entry(create_window)
    name_entry.pack()

    tk.Label(create_window, text="Account Number:").pack()
    accnum_entry = tk.Entry(create_window)
    accnum_entry.pack()

    tk.Label(create_window, text="Password:").pack()
    pword_entry = tk.Entry(create_window, show="*")
    pword_entry.pack()

    tk.Label(create_window, text="Email:").pack()  # Add an email field
    email_entry = tk.Entry(create_window)
    email_entry.pack()

    tk.Button(create_window, text="Submit", command=submit).pack()

def deposit_money():
    def submit():
        accnum = accnum_entry.get()
        amount = amount_entry.get()

        # Account number and amount should be integers
        try:
            accnum = int(accnum)
            amount = float(amount)
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers!")
            return

        if accnum in users:
            result = users[accnum].deposit(accnum, amount)
            messagebox.showinfo("Result", result)
        else:
            messagebox.showerror("Error", "Account not found!")
        deposit_window.destroy()

    deposit_window = tk.Toplevel(root)
    deposit_window.title("Deposit Money")
    deposit_window.geometry("500x320")

    tk.Label(deposit_window, text="Account Number:").pack()
    accnum_entry = tk.Entry(deposit_window)
    accnum_entry.pack()

    tk.Label(deposit_window, text="Amount:").pack()
    amount_entry = tk.Entry(deposit_window)
    amount_entry.pack()

    tk.Button(deposit_window, text="Submit", command=submit).pack()

def withdraw_money():
    def submit():
        accnum = accnum_entry.get()
        amount = amount_entry.get()
        pword = pword_entry.get()

        try:
            accnum = int(accnum)
            amount = float(amount)
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers!")
            return

        if accnum in users:
            result = users[accnum].withdraw(accnum, amount, pword)
            messagebox.showinfo("Result", result)
        else:
            messagebox.showerror("Error", "Account not found!")
        withdraw_window.destroy()

    withdraw_window = tk.Toplevel(root)
    withdraw_window.title("Withdraw Money")
    withdraw_window.geometry("500x320")

    tk.Label(withdraw_window, text="Account Number:").pack()
    accnum_entry = tk.Entry(withdraw_window)
    accnum_entry.pack()

    tk.Label(withdraw_window, text="Amount:").pack()
    amount_entry = tk.Entry(withdraw_window)
    amount_entry.pack()

    tk.Label(withdraw_window, text="Password:").pack()
    pword_entry = tk.Entry(withdraw_window, show="*")
    pword_entry.pack()

    tk.Button(withdraw_window, text="Submit", command=submit).pack()

def view_info():
    def submit():
        accnum = accnum_entry.get()
        pword = pword_entry.get()

        try:
            accnum = int(accnum)
        except ValueError:
            messagebox.showerror("Error", "Account number must be a number!")
            return

        if accnum in users:
            result = users[accnum].display_info(accnum, pword)
            messagebox.showinfo("Account Info", result)
        else:
            messagebox.showerror("Error", "Account not found!")
        info_window.destroy()

    info_window = tk.Toplevel(root)
    info_window.title("View Account Info")
    info_window.geometry("500x320")

    tk.Label(info_window, text="Account Number:").pack()
    accnum_entry = tk.Entry(info_window)
    accnum_entry.pack()

    tk.Label(info_window, text="Password:").pack()
    pword_entry = tk.Entry(info_window, show="*")
    pword_entry.pack()

    tk.Button(info_window, text="Submit", command=submit).pack()

def view_all_accounts():
    accounts = "\n".join([f"{acc}: {user.name}, Balance: {user.balance}" for acc, user in users.items()])
    if not accounts:
        messagebox.showinfo("No Accounts", "No accounts found!")
    else:
        messagebox.showinfo("All Accounts", accounts)

def delete_account():
    def submit():
        accnum = accnum_entry.get()
        pword = pword_entry.get()

        try:
            accnum = int(accnum)
        except ValueError:
            messagebox.showerror("Error", "Account number must be a number!")
            return

        if accnum in users:
            result = users[accnum].check_password(pword)
            if result:
                del users[accnum]
                messagebox.showinfo("Success", "Account deleted successfully!")
            else:
                messagebox.showerror("Error", "Invalid password, unable to delete account.")
        else:
            messagebox.showerror("Error", "Account not found!")

    delete_window = tk.Toplevel(root)
    delete_window.title("Delete Account")
    delete_window.geometry("500x320")

    tk.Label(delete_window, text="Account Number:").pack()
    accnum_entry = tk.Entry(delete_window)
    accnum_entry.pack()

    tk.Label(delete_window, text="Password:").pack()
    pword_entry = tk.Entry(delete_window, show="*")
    pword_entry.pack()

    tk.Button(delete_window, text="Submit", command=submit).pack()

# Main GUI
root = tk.Tk()
root.title("Secure Chat System")
root.geometry("500x320")

tk.Button(root, text="Create Account", command=create_account).pack(pady=10)
tk.Button(root, text="Deposit Money", command=deposit_money).pack(pady=10)
tk.Button(root, text="Withdraw Money", command=withdraw_money).pack(pady=10)
tk.Button(root, text="View Account Info", command=view_info).pack(pady=10)
tk.Button(root, text="View All Accounts", command=view_all_accounts).pack(pady=10)
tk.Button(root, text="Delete Account", command=delete_account).pack(pady=10)

root.mainloop()
