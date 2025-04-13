import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import base64

# Initialize session state
def init_session():
    session_defaults = {
        'stored_data': {},
        'failed_attempts': 0,
        'current_page': 'home',
        'auth': False
    }
    for key, value in session_defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session()
SYSTEM_PASSWORD = "admin123"

# Security functions
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def get_fernet_key(passkey: str) -> bytes:
    hashed = hashlib.sha256(passkey.encode()).digest()[:32]
    return base64.urlsafe_b64encode(hashed)

def encrypt_data(data: str, passkey: str) -> str:
    return Fernet(get_fernet_key(passkey)).encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, passkey: str) -> str:
    return Fernet(get_fernet_key(passkey)).decrypt(encrypted_data.encode()).decode()

# Navigation Sidebar
def sidebar_nav():
    if st.session_state.current_page != 'login':
        with st.sidebar:
            st.title("🔐 Navigation")
            nav_choice = st.radio(
                "Go to:",
                ["🏠 Home", "📥 Store Data", "📤 Retrieve Data"],
                index=["home", "store", "retrieve"].index(st.session_state.current_page)
            )
            
            if nav_choice == "🏠 Home":
                st.session_state.current_page = 'home'
            elif nav_choice == "📥 Store Data":
                st.session_state.current_page = 'store'
            elif nav_choice == "📤 Retrieve Data":
                st.session_state.current_page = 'retrieve'
        st.markdown("---")
        st.caption("Made with ❤️ by **psqasim**  \n© 2024 SecureVault. All rights reserved")
        
# Page components
def home_page():
    st.title("🔒 Secure Data Storage System")
    st.markdown("""
    ### Welcome to Secure Vault
    **Store and retrieve sensitive data securely**
    - Use the sidebar to navigate
    - All data encrypted in-memory
    - Three attempt lockout system
    """)

def store_page():
    st.title("📥 Store Data")
    with st.form("store_form"):
        data = st.text_area("Enter sensitive data:", height=150)
        passkey = st.text_input("Create passkey:", type="password")
        
        if st.form_submit_button("🔒 Encrypt & Store"):
            if data and passkey:
                entry_id = f"entry_{len(st.session_state.stored_data)+1}"
                st.session_state.stored_data[entry_id] = {
                    "encrypted_text": encrypt_data(data, passkey),
                    "passkey": hash_passkey(passkey)
                }
                st.success("Data encrypted and stored successfully!")
            else:
                st.warning("Please fill both fields!")

def retrieve_page():
    st.title("📤 Retrieve Data")
    with st.form("retrieve_form"):
        passkey = st.text_input("Enter passkey:", type="password")
        submitted = st.form_submit_button("🔓 Decrypt")
    
    if submitted:
        hashed = hash_passkey(passkey)
        matches = [e for e in st.session_state.stored_data.values() if e['passkey'] == hashed]
        
        if matches:
            try:
                decrypted = "\n\n".join([decrypt_data(e['encrypted_text'], passkey) for e in matches])
                st.success(f"**Decrypted Data:**\n\n{decrypted}")
            except Exception as e:
                st.error(f"Decryption failed: {str(e)}")
            st.session_state.failed_attempts = 0
        else:
            st.session_state.failed_attempts += 1
            st.error(f"Invalid passkey (Attempt {st.session_state.failed_attempts}/3)")
            
            if st.session_state.failed_attempts >= 3:
                st.session_state.current_page = 'login'

def login_page():
    st.title("🔑 Admin Login")
    with st.form("login_form"):
        password = st.text_input("System password:", type="password")
        if st.form_submit_button("Authenticate"):
            if password == SYSTEM_PASSWORD:
                st.session_state.failed_attempts = 0
                st.session_state.current_page = 'home'
                st.rerun()
            else:
                st.error("Incorrect password!")

# Main app logic
def main():
    sidebar_nav()
    
    if st.session_state.current_page == 'home':
        home_page()
    elif st.session_state.current_page == 'store':
        store_page()
    elif st.session_state.current_page == 'retrieve':
        retrieve_page()
    elif st.session_state.current_page == 'login':
        login_page()
    
    

if __name__ == "__main__":
    main()