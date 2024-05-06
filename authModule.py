# Created the hash function to generate the new salt 
# Check password function 
# Authentication performed 
# User register and login 


import streamlit as st
import pandas as pd
from datetime import datetime
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
import hashlib 



def hash_password(password):
    salt = os.urandom(16)  # Generate a new salt
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    salted_hash = salt + pwd_hash
    return base64.b64encode(salted_hash).decode()  # Store the salt and hash as a single encoded string

def check_password(stored_password, provided_password):
    decoded = base64.b64decode(stored_password)
    salt = decoded[:16]  # The first 16 bytes are the salt
    stored_hash = decoded[16:]  # The rest is the hash
    new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt, 100000)
    return new_hash == stored_hash


# Load dataframes
accounts_df = load_data(ACCOUNTS_FILE, ['Account Number', 'Name', 'Account Type', 'Balance'])
transactions_df = load_data(TRANSACTIONS_FILE, ['Date', 'Type', 'From', 'To', 'Amount'])
users_df = load_data(USERS_FILE, ['Username', 'Password'])
services_df = load_data(SERVICES_FILE, ['Account Number', 'Service Type', 'Status'])
recurring_df = load_data(RECURRING_FILE, ['Account Number', 'Payment Type', 'Amount', 'Frequency', 'Next Due'])
# Authentication functions
def register_user(username, password):
    if username in users_df['Username'].values:
        st.error("Username already exists.")
    else:
        encrypted_password = hash_password(password)
        users_df.loc[len(users_df) + 1] = [username, encrypted_password]
        save_data(users_df, USERS_FILE)
        st.success("User registered successfully!")

def login_user(username, password):
    user_record = users_df[users_df['Username'] == username]
    if not user_record.empty and check_password(user_record.iloc[0]['Password'], password):
        st.session_state['logged_in'] = True
        st.session_state['user'] = username
        logging.info(f"User {username} logged in.")
        return True
    else:
        return False

def show_login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login"):
        if login_user(username, password):
            st.success("Logged in successfully.")
            st.experimental_rerun()
        else:
            st.error("Incorrect username or password.")

def show_registration():
    st.subheader("Register")
    username = st.text_input("Choose a Username", key="reg_username")
    password = st.text_input("Set a Password", type="password", key="reg_password")
    if st.button("Register"):
        register_user(username, password)


# Main function to run the Streamlit app
def main():
    st.title('Advanced Banking Application')
    if 'logged_in' not in st.session_state:
        auth_choice = st.sidebar.selectbox('Authentication', ['Login', 'Register'])
        if auth_choice == 'Login':
            show_login()
        elif auth_choice == 'Register':
            show_registration()
    else:
        menu = ['Create Account', 'Edit Account Details', 'Close Account', 'Deposit Cash', 'Withdraw Cash', 'Transfer Funds', 'View Account Information', 'Manage Services', 'Setup Recurring Payments']
        choice = st.sidebar.selectbox('Select Option', menu)
        if choice == 'Create Account':
            create_account()
        elif choice == 'Edit Account Details':
            edit_account_details()
        elif choice == 'Close Account':
            close_account()
        elif choice == 'Deposit Cash':
            deposit_cash()
        elif choice == 'Withdraw Cash':
            withdraw_cash()
        elif choice == 'Transfer Funds':
            transfer_funds()
        elif choice == 'View Account Information':
            view_account_info()
        elif choice == 'Manage Services':
            manage_services()
        elif choice == 'Setup Recurring Payments':
            setup_recurring_payments()

if __name__ == "__main__":
    main()
