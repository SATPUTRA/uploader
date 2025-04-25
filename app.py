import streamlit as st
import os
import bcrypt
import json
from pathlib import Path
import re

# Initialize directories and metadata file
UPLOAD_DIR = "uploads"
METADATA_FILE = "file_metadata.json"
Path(UPLOAD_DIR).mkdir(exist_ok=True)

# Initialize metadata file if it doesn't exist
if not os.path.exists(METADATA_FILE):
    with open(METADATA_FILE, "w") as f:
        json.dump({}, f)

# Load and migrate metadata
def load_metadata():
    with open(METADATA_FILE, "r") as f:
        metadata = json.load(f)
    
    # Migrate old metadata entries
    updated = False
    for key, data in metadata.items():
        if "folder" not in data:
            # Assume old file is in 'default' folder
            folder = "default"
            old_file_path = os.path.join(UPLOAD_DIR, key)
            new_file_path = os.path.join(UPLOAD_DIR, folder, key)
            
            # Move file to default folder if it exists
            if os.path.exists(old_file_path):
                Path(os.path.join(UPLOAD_DIR, folder)).mkdir(exist_ok=True)
                os.rename(old_file_path, new_file_path)
            
            # Update metadata
            metadata[key] = {
                "folder": folder,
                "password": data["password"]
            }
            updated = True
    
    # Save migrated metadata
    if updated:
        save_metadata(metadata)
    
    return metadata

# Save metadata
def save_metadata(metadata):
    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=4)

# Hash password
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Verify password
def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Sanitize folder name
def sanitize_folder_name(folder_name):
    # Remove invalid characters and limit length
    sanitized = re.sub(r'[^\w\-]', '_', folder_name.strip())
    return sanitized[:50] or "default"

# Streamlit app
st.title("File Upload and Retrieve App")

# Tabs for Upload and Retrieve
tab1, tab2 = st.tabs(["Upload File", "Retrieve File"])

# Upload File Tab
with tab1:
    st.header("Upload a File")
    folder_name = st.text_input("Enter folder name for this file")
    
    if folder_name:
        sanitized_folder = sanitize_folder_name(folder_name)
        uploaded_file = st.file_uploader("Choose a file (including zip)", type=None, key="uploader")
        password = st.text_input("Set a password for this file", type="password")
        
        if st.button("Upload"):
            if uploaded_file and password:
                # Create folder path
                folder_path = os.path.join(UPLOAD_DIR, sanitized_folder)
                Path(folder_path).mkdir(exist_ok=True)
                
                # Save file
                file_path = os.path.join(folder_path, uploaded_file.name)
                with open(file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                
                # Update metadata
                metadata = load_metadata()
                metadata_key = f"{sanitized_folder}/{uploaded_file.name}"
                metadata[metadata_key] = {
                    "folder": sanitized_folder,
                    "password": hash_password(password)
                }
                save_metadata(metadata)
                st.success(f"File '{uploaded_file.name}' uploaded to folder '{sanitized_folder}' successfully!")
            else:
                st.error("Please upload a file and provide a password.")
    else:
        st.info("Please enter a folder name to proceed.")

# Retrieve File Tab
with tab2:
    st.header("Retrieve a File")
    metadata = load_metadata()
    
    # Get unique folder names
    folders = sorted(set([data["folder"] for data in metadata.values()]))
    
    if folders:
        selected_folder = st.selectbox("Select a folder", folders, key="folder_select")
        
        if selected_folder:
            # Filter files in selected folder
            file_names = [key.split("/")[-1] for key, data in metadata.items() if data["folder"] == selected_folder]
            
            if file_names:
                selected_file = st.selectbox("Select a file to retrieve", file_names, key="file_select")
                password = st.text_input("Enter the password for this file", type="password", key="retrieve_password")
                
                if st.button("Download"):
                    if password:
                        metadata_key = f"{selected_folder}/{selected_file}"
                        file_metadata = metadata.get(metadata_key)
                        if file_metadata and verify_password(password, file_metadata["password"]):
                            file_path = os.path.join(UPLOAD_DIR, selected_folder, selected_file)
                            if os.path.exists(file_path):
                                with open(file_path, "rb") as f:
                                    st.download_button(
                                        label="Download File",
                                        data=f,
                                        file_name=selected_file,
                                        mime="application/octet-stream"
                                    )
                            else:
                                st.error("File not found on server.")
                        else:
                            st.error("Incorrect password.")
                    else:
                        st.error("Please enter a password.")
            else:
                st.info("No files in this folder.")
    else:
        st.info("No folders or files uploaded yet.")