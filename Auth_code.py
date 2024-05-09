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

# Setup basic configuration for logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# Security and encryption functions
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



USERS_FILE = 'users.csv'


# Helper functions for CSV operations
def load_data(file_path, columns):
    try:
        return pd.read_csv(file_path, index_col=0)
    except FileNotFoundError:
        logging.error(f"{file_path} not found, creating new dataframe.")
        return pd.DataFrame(columns=columns)

def save_data(df, file_path):
    try:
        df.to_csv(file_path)
    except Exception as e:
        logging.error(f"Failed to save data to {file_path}: {str(e)}")





# Load dataframes
users_df = load_data(USERS_FILE, ['Username', 'Password'])

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
    
if __name__ == "__main__":
    main()
