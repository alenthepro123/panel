import streamlit as st
from streamlit_option_menu import option_menu
import pandas as pd
import hashlib
import os

# Simulated User Database (Replace with a real database)
USER_DB = {
    'admin1@example.com': hashlib.sha256('admin123'.encode()).hexdigest(),
    'admin2@example.com': hashlib.sha256('admin456'.encode()).hexdigest(),
    'admin3@example.com': hashlib.sha256('admin789'.encode()).hexdigest()
}

# Helper: Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Initialize session state for user data if not exists
if 'registered_users' not in st.session_state:
    st.session_state.registered_users = {}
if 'feedbacks' not in st.session_state:
    st.session_state.feedbacks = []  # Format: [{'email': str, 'message': str, 'reply': str}]
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.email = None
    st.session_state.is_admin = False

# Login Function
def login(email, password):
    hashed = hash_password(password)
    return USER_DB.get(email) == hashed or st.session_state.registered_users.get(email) == hashed

# Main Application
st.set_page_config(page_title="SenyasPinoy", page_icon="🤟", layout="wide")

# Login / Register Page
if not st.session_state.logged_in:
    st.image("logo2123.png", width=150)
    st.title("🤟 SenyasPinoy Login")
    option = st.radio("Choose an option:", ["Login", "Register"], horizontal=True)
    
    email = st.text_input("Email", placeholder="Enter your email")
    password = st.text_input("Password", type="password", placeholder="Enter your password")
    
    if option == "Login":
        login_button = st.button("Login")
        if login_button:
            if login(email, password):
                st.session_state.logged_in = True
                st.session_state.email = email
                st.session_state.is_admin = email in USER_DB
                st.success("Login successful! Redirecting...")
            else:
                st.error("Invalid credentials. Please try again.")
    
    elif option == "Register":
        register_button = st.button("Register")
        if register_button:
            if email and password:
                if email in USER_DB or email in st.session_state.registered_users:
                    st.error("Email already exists. Please log in.")
                else:
                    st.session_state.registered_users[email] = hash_password(password)
                    st.success("Registration successful! Please log in.")
            else:
                st.error("Please enter both email and password.")
else:
    # Admin Panel Navigation
    with st.sidebar:
        st.image("placeholder.jpg", width=80)
        st.write(f"### {st.session_state.email}")
        selected = option_menu(
            menu_title="Admin Panel" if st.session_state.is_admin else "User Panel",
            options=["Dashboard", "Content Management", "Support Requests", "Logout"] if st.session_state.is_admin else ["Dashboard", "Feedback", "Logout"],
            icons=["house", "folder", "envelope", "box-arrow-right"] if st.session_state.is_admin else ["house", "envelope", "box-arrow-right"],
            menu_icon="cast",
            default_index=0
        )
    
    # Logout Functionality
    if selected == "Logout":
        st.session_state.clear()
        st.experimental_set_query_params()  # Ensures app refresh

    # Dashboard Section
    elif selected == "Dashboard":
        st.title("📊 Dashboard")
        st.write(f"Welcome, **{st.session_state.email}**!")
        st.metric("Total Users", len(st.session_state.registered_users))

    # Content Management Section (Admin Only)
    elif selected == "Content Management" and st.session_state.is_admin:
        st.title("📂 Content Management")
        
        categories = ["Alphabet", "Food", "Places", "Greetings", "Animals"]
        st.write("Manage content categories")

        # Add New Category
        new_category = st.text_input("Add New Category")
        if st.button("Add Category"):
            categories.append(new_category)
            st.success(f"Category '{new_category}' added!")

        # Display existing categories and allow media upload
        category = st.selectbox("Select Category to Manage", categories)
        media_file = st.file_uploader("Upload Image or Video", type=["jpg", "png", "jpeg", "mp4", "mov"])

        if media_file is not None:
            file_extension = media_file.name.split('.')[-1].lower()
            if file_extension in ['jpg', 'png', 'jpeg']:
                # If it's an image
                st.image(media_file, caption="Uploaded Image", use_column_width=True)
                # Optionally, you can save this file for later use if needed
                if not os.path.exists("uploaded_files"):
                    os.makedirs("uploaded_files")
                with open(f"uploaded_files/{media_file.name}", "wb") as f:
                    f.write(media_file.getbuffer())
                st.success(f"Image uploaded successfully to {category}!")
            elif file_extension in ['mp4', 'mov']:
                # If it's a video
                st.video(media_file, caption="Uploaded Video")
                # Save the video file
                if not os.path.exists("uploaded_files"):
                    os.makedirs("uploaded_files")
                with open(f"uploaded_files/{media_file.name}", "wb") as f:
                    f.write(media_file.getbuffer())
                st.success(f"Video uploaded successfully to {category}!")
            else:
                st.error("Unsupported file type. Please upload an image or video.")

    # Support Requests Section (Admin Only)
    elif selected == "Support Requests" and st.session_state.is_admin:
        st.title("📩 Support Requests")
        if st.session_state.feedbacks:
            for i, feedback in enumerate(st.session_state.feedbacks):
                st.write(f"**From:** {feedback['email']}")
                st.write(f"**Message:** {feedback['message']}")
                st.text_area("Reply", value=feedback.get('reply', ''), key=f"reply_{i}")
                if st.button(f"Send Reply to {feedback['email']}", key=f"send_reply_{i}"):
                    st.session_state.feedbacks[i]['reply'] = st.session_state[f"reply_{i}"]
                    st.success(f"Reply sent to {feedback['email']}!")
        else:
            st.write("No new support requests.")

    # Feedback Section (Users Only)
    elif selected == "Feedback" and not st.session_state.is_admin:
        st.title("📝 Submit Feedback")
        feedback_message = st.text_area("Enter your feedback")
        if st.button("Submit Feedback"):
            if feedback_message:
                st.session_state.feedbacks.append({'email': st.session_state.email, 'message': feedback_message, 'reply': None})
                st.success("Thank you for your feedback!")
            else:
                st.error("Please enter a feedback message.")
        
        st.title("📬 Feedback Replies")
        for feedback in st.session_state.feedbacks:
            if feedback['email'] == st.session_state.email and feedback['reply']:
                st.write(f"**Message:** {feedback['message']}")
                st.write(f"**Reply:** {feedback['reply']}")







