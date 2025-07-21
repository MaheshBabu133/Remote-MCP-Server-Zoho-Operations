from fastmcp import FastMCP
import requests
from typing import Optional, List, Dict, Union
import json
from datetime import datetime, timezone
import random, string
import os
import imaplib
import email
import hashlib
import time
import re
import socket
import ssl
from email.header import decode_header
from requests import Response
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formatdate, make_msgid, formataddr
from email.header import Header
import base64
import tempfile
from urllib.parse import urlparse

# Create MCP instance
mcp = FastMCP("Zoho_all_operation")

# Authentication management
@mcp.tool()
def Refresh_Token_Parameter_Admin_Guide():
    '''
    Provide a clear and comprehensive step-by-step guide for generating a refresh token for the Zoho Mail API. The guide should be suitable for a first-time setup and must include:

    1. Instructions on how to register a self-client application in the Zoho Developer Console to obtain the client ID and client secret.
    2. Steps to generate an authorization code, including:
       - Required scopes for accessing Zoho Mail and account settings
       - Duration settings
       - Scope description
    3. The exact API request (with endpoint, method, headers, and body format) to exchange the authorization code for a refresh token.
    4. A list of common errors (e.g., invalid scopes, expired codes, incorrect credentials) with explanations and troubleshooting steps.
    5. Security best practices for storing and managing the refresh token securely.

    The explanation should be user-friendly, ordered logically, and detailed enough for someone without prior Zoho API experience.
    '''

    description = """
    Step-by-Step Guide: How to Generate a Zoho Mail API Refresh Token (Admin Access)

    This guide will help you generate a **refresh token** required to access Zoho Mail and organization-level APIs. Follow the steps below carefully:

    ### Step 1: Create an Self Clinet Application in Zoho Developer Console
    1. Visit the Zoho API Console: https://api-console.zoho.com
    2. Create a **new self-client application**.
    3. Once created, click on **Client Secret** to view the credentials.
    4. Note down your **CLIENT_ID** and **CLIENT_SECRET** — you’ll need these later.

    ### Step 2: Generate an Authorization Code
    1. In the same app, click the **Generate Code** button.
    2. For the **Scope**, enter:
       ```
       ZohoMail.messages.ALL,ZohoMail.organization.accounts.ALL,ZohoMail.organization.accounts.UPDATE,ZohoMail.folders.READ
       ```
    3. Set a **time duration** (suggested: 10 minutes).
    4. Enter a **Scope Description** (Suggested: Zoho email and account operations).
    5. Click **Create** and copy the generated **Authorization Code**.

    ### Step 4: Exchange Authorization Code for Refresh Token
    Before the authorization code expires, make the following API call:

    call the `Refresh_Token_Generator` function with the following parameters:
    - `CLIENT_ID`: your client ID
    - `CLIENT_SECRET`: your client secret
    - `authorization_code`: the authorization code you received
    - `REDIRECT_URI`: the redirect URI you registered(default: http://localhost:8000/callback)

    ### Step 5: Notes & Best Practices
    - The **refresh token** is a one-time token used to generate access tokens for API calls.
    - **Store the refresh token securely** — it grants long-term access to your Zoho data.
    - If something goes wrong:
        - Double-check the **scope** format.
        - Make sure the **authorization code hasn’t expired**.
        - Ensure the **redirect URI** matches what’s registered in the console.
        - Confirm the **client ID/secret** are correct.

    That’s it! You're now ready to use your refresh token for accessing Zoho Mail APIs securely.
    """
    return description

@mcp.tool()
def Refresh_Token_Generator(CLIENT_ID,CLIENT_SECRET,authorization_code,REDIRECT_URI = "http://localhost:8000/callback"):

    """
    Generates and stores Zoho OAuth refresh token using the authorization code flow.
    
    parameters:
        CLIENT_ID: exact Zoho OAuth client ID
        CLIENT_SECRET: exact Zoho OAuth client secret
        authorization_code: exact Temporary code received after user authorization
        REDIRECT_URI: Redirect URI registered with Zoho (default: http://localhost:8000/callback)

    return: 
        Refresh token as a string if successful, otherwise return an refresh_token_parameter_admin_guide

    Note:
        - required parameters are not found in the arguments ask for an user to provide the required parameters
    """


    # Prepare data for token exchange
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code": authorization_code
    }
    TOKEN_URL = "https://accounts.zoho.in/oauth/v2/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(TOKEN_URL, headers=headers,data=data)
    
    extra_data = {"CLIENT_ID": CLIENT_ID,
        "CLIENT_SECRET": CLIENT_SECRET}

    file_path ="token.txt"

    if response.status_code == 200:
        tokens = response.json()
        if tokens.get("refresh_token"):
            try:
                # Write the dictionary to token.txt file as JSON
                with open(file_path, 'w') as file:
                    # Convert the dictionary to a JSON string and write to the file
                    tokens.update(extra_data)
                    json.dump(tokens, file)
                print("Tokens written successfully!")

            except Exception as e:
                print(f"Failed to write the file: {e}")
    else:
        
        if (not os.path.exists(file_path)):
            extra_data["refresh_token"] = "Invalid Token"
            with open(file_path,'w') as file: json.dump(extra_data,file)
        return f"No Tokens were generated"


    if not os.path.exists(file_path) or str(os.path.getsize(file_path)) == '0' :
        extra_data["refresh_token"] = "Invalid Token"
        with open(file_path,'w') as file: json.dump(extra_data,file)
    
    with open(file_path,'r') as file:
        data = json.loads(file.read())

    if "refresh_token" in str(data):
        return data["refresh_token"]
    
    else:
        with open(file_path, 'w') as file:
        # Convert the dictionary to a JSON string and write to the file
            extra_data["refresh_token"] = "Invalid Token"
            json.dump(extra_data, file)
        return "Perform with the valid parameters"

@mcp.tool()
def Access_Token_Generator() -> Optional[str]:
    """
    Generate an access token for Zoho API using a refresh token.
    
    return: 
        Access token as a string if successful, otherwise return an refresh_token_parameter_admin_guide
        
    """
    try:
        with open("token.txt","r") as file:
            data= json.loads(file.read())
        refresh_token = data["refresh_token"]
        CLIENT_ID = data["CLIENT_ID"]
        CLIENT_SECRET = data["CLIENT_SECRET"]
        
        print("CLIENT_ID",CLIENT_ID,"CLIENT_SECRET",CLIENT_SECRET,"refresh_token",refresh_token,sep="\n")
    except:
        return refresh_token_parameter_guide
   
    url = 'https://accounts.zoho.in/oauth/v2/token' 

    data = {
        'grant_type': 'refresh_token',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'refresh_token': refresh_token
        }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        tokens = response.json()
        if "access_token" in str(tokens):
            return tokens['access_token']
        else:
            return refresh_token_parameter_guide
    else:
        print("Error:", response.status_code, response.text)
        return refresh_token_parameter_guide



# General Functionalities
@mcp.tool()
def encode_time(timestamp_ms):
    """
    Convert a timestamp in milliseconds to a UTC datetime string.
    
    Parameters:
    timestamp_ms (int): The timestamp in milliseconds
    """
    if timestamp_ms is None:
        return None
    timestamp_s = int(timestamp_ms) / 1000
    dt = datetime.fromtimestamp(timestamp_s, tz=timezone.utc)  # timezone-aware datetime in UTC
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

@mcp.tool()
def Generate_Custom_Password():
    """
    Generate a custom password with the following structure:
    - First letter: Uppercase
    - Next 3 letters: Lowercase
    - Next 5 characters: '@' symbol
    - Last 3 characters: Numerical digits
    return: 
        Generated custom password
    """
    # Generate the components
    first_letter = random.choice(string.ascii_uppercase)  # First letter (uppercase)
    next_three_letters = ''.join(random.choice(string.ascii_lowercase) for _ in range(3))  # Next 3 lowercase letters
    at_symbols = '@'  # Five '@' symbols
    last_three_digits = ''.join(random.choice(string.digits) for _ in range(3))  # Last 3 digits

    # Combine all components to form the password
    password = first_letter + next_three_letters + at_symbols + last_three_digits
    return password



# User management
@mcp.tool()
def Get_All_User_Info(Access_Token):
    """
    Fetch all user accounts from Zoho Mail and return storage info per user.
    
    parameters:
        Access_Token: call the tool Access_Token_Generator to get the access token.
    
    return: 
        List of dictionaries containing user information and storage details.
    
    Note:
        - required parameters are not found in the arguments ask for an user to provide the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.

    """
    BASE_URL = "https://mail.zoho.in/api"
    HEADERS = {
        "Authorization": f"Zoho-oauthtoken {Access_Token}",
        "Content-Type": "application/json"
    }


    url = f"{BASE_URL}/organization/accounts"
    response = requests.get(url, headers=HEADERS)

    if response.status_code != 200:
        print("Failed to fetch accounts")
        print(response.status_code, response.text)
        return []

    accounts = response.json().get("data", [])
    print(f"Found {len(accounts)} account(s).")

    # Extract zoid from policyId of the first user
    first_policy = accounts[0].get("policyId", {})
    zoid = first_policy.get("zoid", "N/A")

    user_info_list = []
    for account in accounts:
        
        used_mb = account.get("usedStorage", 0)
        allowed_kb = account.get("allowedStorage", 0)
        total_mb = allowed_kb / 1024
        available_mb = total_mb - used_mb

        storage = {
            "total_storage_mb": round(total_mb, 2),
            "used_storage_mb": round(used_mb, 2),
            "available_storage_mb": round(available_mb, 2),
        }
        account.update(storage)

        
    return accounts

@mcp.tool()
def Create_Zoho_Mail_User(Access_Token,firstName: str,zoid,domain,password=Generate_Custom_Password,lastName="") -> dict:
    """
    Creates a user in Zoho Mail with required fields and default values for optional fields.
    
    parameters:
        Access_Token: call the tool Access_Token_Generator to get the access token
        zoid: exact Zoho organization ID
        domain: exact domain name
        password: password for the user (if not provided, a custom password will be generated)
        firstName: first name of the user
        lastName(optional): last name of the user
    
    return: 
        Response dictionary from Zoho API
    
    Note:
        - If the required parameters are not found in the arguments, first call the tool Get_All_User_Info to retrieve them. If they are still not found, ask the user for the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.

    """
    # zoid = "60041990901"           # Replace with your actual organization ID
    # domain = "maheshbabu.mywp.info"
    
    # ✅ Prepare payload with defaults for optional fields
    payload = {
        "primaryEmailAddress": f"{firstName}@{domain}",
        "password": password,
        "firstName": firstName,
        "lastName": lastName,
        "displayName": f"{firstName} {lastName}",
        "role": "member",  # Default to "member"
        "country": "IN",  # Default to "IN"
        "language": "en",  # Default to English
        "timeZone": "Asia/Kolkata",  # Default to India time
        "oneTimePassword": False,
        "groupMailList": []
    }

    # 🌐 Endpoint - Using correct API endpoint
    url = f"https://mail.zoho.in/api/organization/{zoid}/accounts"
    
    # 🧾 Headers
    headers = {
        "Authorization": f"Zoho-oauthtoken {Access_Token}",
        "Content-Type": "application/json"
    }

    # 🚀 Make the request
    response = requests.post(url, headers=headers, json=payload)
    data = response.json()
    # 📋 Handle response
    if response.status_code == 200:
        zuid = data["data"]["zuid"]
        mail_id = data["data"]["emailAddress"][0]["mailId"]
        zoid = data["data"]["policyId"]["zoid"]
        role = data["data"]["role"]
        user_first_name = data["data"]["firstName"]
        user_last_name = data["data"]["lastName"]
        imap_access_enabled = data["data"]["imapAccessEnabled"]
        account_id = data["data"]["accountId"]
        print("User created successfully.")
        print("username:", mail_id,"password:",password)
        print("**Note**\nSave you password you wont be able to see it again due to hashing")
        return {"zuid": zuid, "mail_id": mail_id, "zoid": zoid, "role": role, "first_name": user_first_name, "last_name": user_last_name, "imap_access_enabled": imap_access_enabled, "account_id": account_id}
    else:
        print("Status Code:", response.status_code)
        print("Response:", response.text)
    # Safely handle response parsing
    try:        
        return response.json()
    except:
        return {"error": response.text}

@mcp.tool()
def Update_IMAP_Status(Access_Token,zoid: str, account_id: str, zuid: str, enable_imap: bool) -> bool:
    """
    Updates the IMAP access status for a specific user account in a Zoho Mail organization.
    
    parameters:
        Access_Token: call the tool Access_Token_Generator to get the access token
        zoid: The exact organization ID (Zoid) of the Zoho Mail tenant.
        account_id: The exact account ID of the user whose IMAP status is being updated.
        zuid: The exact Zoho User ID (ZUID) of the target user.
        enable_imap: Set to True to enable IMAP, or False to disable it.
    
    return: 
        True if the IMAP status was updated successfully, False otherwise

    Note:
        - If the required parameters are not found in the arguments, first call the tool Get_All_User_Info to retrieve them. If they are still not found, ask the user for the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.
    """
    url = f"https://mail.zoho.in/api/organization/{zoid}/accounts/{account_id}"
    headers = {
        "Authorization": f"Zoho-oauthtoken {Access_Token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "zuid": zuid,
        "mode": "updateIMAPStatus",
        "imapAccessEnabled": enable_imap # if True Means enable False means disable
    }

    response = requests.put(url, headers=headers, json=payload)
    if response.status_code == 200:
        print("IMAP status updated successfully.")
        print(response.json())
        return True
    else:
        print(f"Failed to update IMAP status: {response.status_code} {response.text}")
        return False

@mcp.tool()
def Delete_User_By_ZUID(Access_Token, zoid, zuid: str):
    """
    Delete a Zoho Mail user using ZUID via the organization accounts API.

    parameters:
        Access_Token: call the tool Access_Token_Generator to get the access token
        zoid: exact organization ID (Zoid) of the Zoho Mail tenant
        zuid: exact Zoho User ID (ZUID) of the target user
    
    return: 
        True if the user was deleted successfully, False otherwise

    Note:
        - If the required parameters are not found in the arguments, first call the tool Get_All_User_Info to retrieve them. If they are still not found, ask the user for the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.
    """

    url = f"https://mail.zoho.in/api/organization/{zoid}/accounts"
    
    headers = {
        "Authorization": f"Zoho-oauthtoken {Access_Token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    payload = {
        "accountList": [zuid]  # Must be a JSON array
    }

    try:
        response = requests.delete(url, headers=headers, data=json.dumps(payload))

        if response.status_code == 200:
            print(f"✅ Successfully deleted user with ZUID: {zuid}")
            print(json.dumps(response.json(), indent=2))
            return True
        else:
            print(f"❌ Failed to delete user with ZUID: {zuid}")
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"❌ Connection error: {e}")
        return False

@mcp.tool()
def Reset_Zoho_Mail_Password(Access_Token, zoid, zuid, new_password) -> bool:
    """
    Reset the password for a specific user account in a Zoho Mail organization.

    parameters:
        Access_Token: call the tool Access_Token_Generator to get the access token
        zoid: exact organization ID (Zoid) of the Zoho Mail tenant
        zuid: exact Zoho User ID (ZUID) of the target user
        new_password: new password for the user if not provided, a custom password will be generated
    return: 
        True if the password was reset successfully, False otherwise

    Note:
        - If the required parameters are not found in the arguments, first call the tool Get_All_User_Info to retrieve them. If they are still not found, ask the user for the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.
    """
    url = f"https://mail.zoho.in/api/organization/{zoid}/accounts/{zuid}"
    
    headers = {
        "Authorization": f"Zoho-oauthtoken {Access_Token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = {
        "password": new_password,
        "mode": "resetPassword",
        "zuid":zuid
    }

    response = requests.put(url, headers=headers, json=payload)
    print(response.json())
    if response.status_code == 200:
        print("Password Update successfully.")
        print(response.json())
        return True
    else:
        print(f"Failed to update Password: {response.status_code} {response.text}")
        return False



#Email Management
@mcp.tool()
def Get_Emails_Zoho_Format(email_id, password, status_type = "All", folder="INBOX"):
    """
    Access emails via IMAP and format response like the Zoho Mail API with consistent message IDs
    Includes body content and improved error handling for socket issues

    parameters:
        email_id: The exact sender's email address (also used for authentication) if not provided, the email_id don't execute ask for an user to provide the email_id
        password: The exact sender's password (also used for authentication) if not provided, the password don't execute ask for an user to provide the password
        status_type: The status type of emails to fetch (default: 'All'). Valid options are: 'All', 'Unread', 'Read'. If an invalid value is provided, default to the closest valid option.
        folder: The folder to search for emails (default: "INBOX")
    returns:
        A list of emails in Zoho Mail API format based on the provided status_type
    """
    try:
        # Connect to IMAP server with a timeout
        mail = imaplib.IMAP4_SSL("imap.zoho.in", timeout=30)
        mail.login(email_id, password)
        
        # Select folder
        mail.select(folder)
        
        # Search for all emails
        status, messages = mail.search(None, "ALL")
        email_ids = messages[0].split()
        
        # Use all emails, no limit
        latest_emails = email_ids
        
        # Calculate batch size - process emails in smaller batches to avoid connection issues
        batch_size = 5000
        
        # Process emails in batches
        emails = []
        for i in range(0, len(latest_emails), batch_size):
            batch = latest_emails[i:i+batch_size]
            
            # Process each batch with fresh connection
            try:
                # Reconnect for each batch to avoid timeouts
                if i > 0:
                    mail.close()
                    mail.logout()
                    mail = imaplib.IMAP4_SSL("imap.zoho.in", timeout=30)
                    mail.login(email_id, password)
                    mail.select(folder)
                
                for email_id in batch:
                    try:
                        # Fetch email headers and flags with retry mechanism
                        retry_count = 0
                        max_retries = 3
                        success = False
                        
                        while retry_count < max_retries and not success:
                            try:
                                status, msg_data = mail.fetch(email_id, "(RFC822)")
                                status, flag_data = mail.fetch(email_id, "(FLAGS)")
                                success = True
                            except (socket.error, imaplib.IMAP4.abort) as e:
                                retry_count += 1
                                if retry_count >= max_retries:
                                    raise
                                print(f"Connection error, retrying {retry_count}/{max_retries}...")
                                # Reconnect
                                try:
                                    mail.close()
                                    mail.logout()
                                except:
                                    pass  # Ignore errors during reconnection
                                mail = imaplib.IMAP4_SSL("imap.zoho.in", timeout=30)
                                mail.login(email_id, password)
                                mail.select(folder)
                                time.sleep(1)  # Wait before retry
                        
                        # Skip if error fetching email
                        if status != 'OK':
                            continue
                            
                        for response in msg_data:
                            if isinstance(response, tuple):
                                raw_email = response[1]
                                msg = email.message_from_bytes(raw_email)
                                
                                # Extract original Message-ID and convert to numeric format
                                orig_msg_id = msg.get("Message-ID", "")
                                
                                if orig_msg_id:
                                    # Remove < > and any non-alphanumeric characters
                                    clean_id = re.sub(r'[<>\s]', '', orig_msg_id)
                                    
                                    # Hash the clean ID to get a consistent value
                                    hash_obj = hashlib.md5(clean_id.encode())
                                    hash_hex = hash_obj.hexdigest()
                                    
                                    # Extract only numeric characters from the hash
                                    numeric_id = ''.join(c for c in hash_hex if c.isdigit())
                                    
                                    # Format like Zoho's IDs (19 digits)
                                    message_id = numeric_id[:19]
                                    
                                    # Ensure the message_id starts with 17 (like examples)
                                    if not message_id.startswith('17'):
                                        message_id = '17' + message_id[2:]
                                else:
                                    # Fallback if no Message-ID is available
                                    # Use stable parts of the email to create a consistent ID
                                    id_parts = [
                                        msg.get("From", ""),
                                        msg.get("To", ""),
                                        msg.get("Subject", ""),
                                        msg.get("Date", "")
                                    ]
                                    
                                    stable_source = "".join(id_parts)
                                    hash_obj = hashlib.md5(stable_source.encode())
                                    hash_hex = hash_obj.hexdigest()
                                    numeric_id = ''.join(c for c in hash_hex if c.isdigit())
                                    message_id = '17' + numeric_id[:17]  # Start with 17, total 19 digits
                                
                                # Generate thread ID using same method but with slight variation
                                references = msg.get("References", msg.get("In-Reply-To", ""))
                                if references:
                                    # Calculate thread ID based on References/In-Reply-To
                                    hash_obj = hashlib.md5(references.encode())
                                    hash_hex = hash_obj.hexdigest()
                                    numeric_thread = ''.join(c for c in hash_hex if c.isdigit())
                                    thread_id = '17' + numeric_thread[:17]
                                else:
                                    # No references, use same as message ID
                                    thread_id = message_id
                                        
                                # Get subject with proper decoding
                                subject = ""
                                if msg["Subject"]:
                                    subject_parts = decode_header(msg["Subject"])
                                    for part, encoding in subject_parts:
                                        if isinstance(part, bytes):
                                            if encoding:
                                                subject += part.decode(encoding, 'replace')
                                            else:
                                                subject += part.decode('utf-8', 'replace')
                                        else:
                                            subject += str(part)
                                
                                # Parse addresses correctly
                                from_addr = msg.get("From", "")
                                from_parts = email.utils.parseaddr(from_addr)
                                from_display = from_parts[0] or from_parts[1].split('@')[0]
                                from_email = from_parts[1]
                                
                                to_addr = msg.get("To", "")
                                cc_addr = msg.get("Cc", "Not Provided")
                                
                                # Extract date and convert to milliseconds timestamp
                                date_tuple = email.utils.parsedate_tz(msg.get("Date", ""))
                                if date_tuple:
                                    sent_date = str(int(email.utils.mktime_tz(date_tuple) * 1000))
                                else:
                                    # Use a fixed timestamp as fallback
                                    sent_date = "1750000000000"
                                
                                # Parse received timestamp
                                received_headers = msg.get_all("Received")
                                received_time = sent_date
                                if received_headers and len(received_headers) > 0:
                                    match = re.search(r';(.*?)(?:\n|$)', received_headers[0])
                                    if match:
                                        recv_date_str = match.group(1).strip()
                                        recv_date_tuple = email.utils.parsedate_tz(recv_date_str)
                                        if recv_date_tuple:
                                            received_time = str(int(email.utils.mktime_tz(recv_date_tuple) * 1000))
                                
                                # Extract message content, body, and summary
                                summary = ""
                                body = ""  # Initialize body variable
                                
                                if msg.is_multipart():
                                    for part in msg.walk():
                                        content_type = part.get_content_type()
                                        if content_type == "text/plain":
                                            try:
                                                payload = part.get_payload(decode=True)
                                                if payload:
                                                    charset = part.get_content_charset() or 'utf-8'
                                                    body = payload.decode(charset, 'replace')
                                                    summary = body.strip().split('\n')[0][:100]
                                                    break
                                            except Exception as e:
                                                print(f"Error extracting text content: {str(e)}")
                                        # If we don't find plain text, try HTML
                                        elif content_type == "text/html" and not body:
                                            try:
                                                payload = part.get_payload(decode=True)
                                                if payload:
                                                    charset = part.get_content_charset() or 'utf-8'
                                                    body = payload.decode(charset, 'replace')
                                                    # Try to extract text from HTML
                                                    summary = re.sub(r'<.*?>', '', body)[:100]
                                            except Exception as e:
                                                print(f"Error extracting HTML content: {str(e)}")
                                else:
                                    try:
                                        payload = msg.get_payload(decode=True)
                                        if payload:
                                            charset = msg.get_content_charset() or 'utf-8'
                                            try:
                                                body = payload.decode(charset, 'replace')
                                                summary = body.strip().split('\n')[0][:100]
                                            except:
                                                body = str(payload)
                                                summary = body[:100]
                                    except Exception as e:
                                        print(f"Error extracting content: {str(e)}")
                                
                                # Extract size
                                size = str(len(raw_email))
                                
                                # Determine folder ID
                                folder_id = "1"  # Default to inbox
                                
                                # Determine read status from flags
                                flag_str = flag_data[0].decode() if flag_data and flag_data[0] else ""
                                is_read = '0'
                                if '\\Seen' in flag_str:
                                    is_read = '1'
                                    
                                # Determine flag status
                                flag_id = "flag_not_set"
                                if '\\Flagged' in flag_str:
                                    flag_id = "important"
                                
                                # Set thread count
                                thread_count = "0"
                                
                                # Check for attachments
                                has_attachment = "0"
                                for part in msg.walk():
                                    if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') and \
                                       'attachment' in part.get('Content-Disposition'):
                                        has_attachment = "1"
                                        break
                                        
                                # Check for inline images
                                has_inline = "false"
                                for part in msg.walk():
                                    if part.get_content_maintype() == 'image' and part.get('Content-Disposition') and \
                                       'inline' in part.get('Content-Disposition'):
                                        has_inline = "true"
                                        break
                                
                                # Create email object in Zoho format
                                email_obj = {
                                    "summary": summary,
                                    "sentDateInGMT": sent_date,
                                    "calendarType": 0,
                                    "subject": subject,
                                    "messageId": message_id,
                                    "threadCount": thread_count,
                                    "flagid": flag_id,
                                    "priority": "3",
                                    "hasInline": has_inline,
                                    "toAddress": to_addr,
                                    "folderId": folder_id,
                                    "ccAddress": cc_addr,
                                    "threadId": thread_id,
                                    "hasAttachment": has_attachment,
                                    "size": size,
                                    "sender": from_display,
                                    "receivedTime": received_time,
                                    "fromAddress": from_email,
                                    "status": is_read,
                                    "imapId": email_id.decode(),  # Store IMAP ID for deletion
                                    "body": body  # Add the full body content
                                }
                                
                                # Add any important headers
                                if 'Reply-To' in msg:
                                    email_obj["replyTo"] = msg['Reply-To']
                                    
                                emails.append(email_obj)
                    except Exception as e:
                        print(f"Error processing email {email_id.decode()}: {str(e)}")
            except Exception as e:
                print(f"Batch error: {str(e)}")
        
        # Ensure we close the connection
        try:
            mail.close()
            mail.logout()
        except:
            pass
        
        if status_type == "All":
            # Return simplified list of emails with key fields
            return emails
        if status_type == "Unread":
            # Return simplified list of unread emails with key fields
            return [ a for a in emails if a["status"] == "0"]
        if status_type == "Read":
            # Return simplified list of read emails with key fields
            return [ a for a in emails if a["status"] == "1"]
        
    except Exception as e:
        # Ensure we clean up on error
        try:
            mail.close()
            mail.logout()
        except:
            pass
        return f"Failed to fetch emails with invalid email credentials : {str(e)} "

@mcp.tool()
def Send_Zoho_Email(email_id, password, to_addresses, subject, body, 
                   attachments=None, html_body=None, cc_addresses=None, 
                   bcc_addresses=None, importance="normal", reply_to=None, 
                   organization=None):
    """
    Send an Email via Zoho Mail (Using Basic Authentication)

    This tool sends an email from a Zoho Mail account using the specified sender credentials.

    Args:
        email_id: The exact sender's email address (also used for authentication) if not provided, the email_id don't execute ask for an user to provide the email_id
        password: The exact sender's password (also used for authentication) if not provided, the password don't execute ask for an user to provide the password
        to_addresses: The exact recipient email address or list of recipient email addresses
        subject: The exact email subject
        body: The exact plain text email body
        attachments: Optional. Various attachment formats supported
        html_body: Optional HTML version of the email body
        cc_addresses: Optional. The exact CC email address or list of CC email addresses
        bcc_addresses: Optional. The exact BCC email address or list of BCC email addresses
        importance: The exact email importance ("high", "normal", "low")
        reply_to: Optional reply-to email address
        organization: Optional organization name
    
    Returns:
        dict: Status of the operation

    Note:
        required parameters are not found in the arguments ask for an user to provide the required parameters.
        If any time field is found in response call the encode_time tool to convert it to UTC datetime string.
    """
    temp_files = []  # Track temp files to clean up later
    
    try:
        # Handle single email address or list
        if isinstance(to_addresses, str):
            to_addresses = [to_addresses]
            
        # Handle CC addresses
        recipient_list = to_addresses.copy()
        if cc_addresses:
            if isinstance(cc_addresses, str):
                cc_addresses = [cc_addresses]
            recipient_list.extend(cc_addresses)
        
        # Handle BCC addresses
        if bcc_addresses:
            if isinstance(bcc_addresses, str):
                bcc_addresses = [bcc_addresses]
            # Add BCC recipients to the recipient list, but don't add them to headers
            recipient_list.extend(bcc_addresses)
        
        print("recipient_list : ",recipient_list)
        # Create message container
        msg = MIMEMultipart('mixed')
        
        # Extract sender name from email if possible
        sender_name = email_id.split('@')[0] if '@' in email_id else email_id
        sender_name = ' '.join(word.capitalize() for word in sender_name.replace('.', ' ').split())
        
        # Add professional headers to improve deliverability
        msg['From'] = formataddr((str(Header(sender_name, 'utf-8')), email_id))
        msg['To'] = ', '.join(to_addresses)
        
        # Use a less spammy subject line
        if subject:
            # Avoid ALL CAPS or excessive punctuation
            if subject.isupper():
                subject = subject.capitalize()
            subject = re.sub(r'[!?]{2,}', '!', subject)  # Reduce multiple !!! or ???
            
            # # Add date to subject to make it unique
            # if not re.search(r'\[\w{3} \d{1,2}\]', subject):
            #     subject += f" [{datetime.now().strftime('%b %d')}]"
                
            msg['Subject'] = subject
            
        msg['Date'] = formatdate(localtime=True)
        
        # Create a proper Message-ID with the sender's domain
        domain = email_id.split('@')[1]
        msg['Message-ID'] = make_msgid(domain=domain)
        
        # Add more headers to improve deliverability
        msg['X-Mailer'] = f"Python Email Client"
        
        if importance.lower() == 'high':
            msg['Importance'] = 'High'
        
        if organization:
            msg['Organization'] = organization
            
        if reply_to:
            msg['Reply-To'] = reply_to
        
        if cc_addresses:
            msg['Cc'] = ', '.join(cc_addresses)
            
        # Add MIME version header
        msg['MIME-Version'] = '1.0'
        
        # Create the alternative part for plain/html content
        alt_part = MIMEMultipart('alternative')
        
        # Attach plain text version with improved formatting
        plain_text = body
        
        # Add a proper signature
        plain_text += f"\n\nBest Regards,\n{sender_name}\n{email_id}"
        
        alt_part.attach(MIMEText(plain_text, 'plain', 'utf-8'))
        
        # Attach HTML version if provided
        if html_body:
            # Extract just the body content if html_body already has HTML structure
            def extract_html_content(html):
                body_match = re.search(r'<body.*?>(.*?)</body>', html, re.DOTALL | re.IGNORECASE)
                if body_match:
                    return body_match.group(1).strip()
                return html
            
            # Get clean content
            content_only = extract_html_content(html_body)
            
            # Ensure HTML has proper structure
            html_body = f"""<!DOCTYPE html>
            <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>{subject}</title>
                </head>


                <body style="font-family: Arial, Helvetica, sans-serif; line-height: 1.6; color: #333333; max-width: 600px; margin: 0 auto; padding: 20px;">
                    {content_only}
                    
                    <div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #dddddd;">
                        <p style="font-size: 14px; color: #555555;">
                            <strong>Best regards,</strong><br>
                            {sender_name}<br>
                            <a href="mailto:{email_id}" style="color: #0066cc; text-decoration: none;">{email_id}</a>
                        </p>
                    </div>
                </body>
            </html>"""
            
            alt_part.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        # Attach the alternative part to the message
        msg.attach(alt_part)
        
        # Process attachments
        if attachments:
            # Convert to list if it's a single item
            if not isinstance(attachments, list):
                attachments = [attachments]
                
            for attachment in attachments:
                # Case 1: It's a regular local file path
                if isinstance(attachment, str) and os.path.isfile(attachment):
                    file_path = attachment
                    file_name = os.path.basename(file_path)
                    
                    with open(file_path, 'rb') as file:
                        part = MIMEApplication(file.read(), Name=file_name)
                        part['Content-Disposition'] = f'attachment; filename="{file_name}"'
                        # Add Content-ID for potential HTML referencing
                        content_id = make_msgid()
                        part['Content-ID'] = content_id
                        msg.attach(part)
                
                # Case 2: It's a URL/cloud link
                elif isinstance(attachment, str) and (attachment.startswith('http://') or attachment.startswith('https://')):
                    try:
                        response = requests.get(attachment, stream=True, timeout=30)
                        if response.status_code == 200:
                            # Get filename from URL or use a default name
                            file_name = os.path.basename(urlparse(attachment).path)
                            if not file_name or file_name == '':
                                # Try to get filename from content-disposition header
                                content_disp = response.headers.get('content-disposition')
                                if content_disp:
                                    fname = re.findall('filename="(.+)"', content_disp)
                                    if fname:
                                        file_name = fname[0]
                                    else:
                                        file_name = 'download.file'
                                else:
                                    file_name = 'download.file'
                            
                            # Download to temp file
                            temp_file = tempfile.NamedTemporaryFile(delete=False)
                            temp_files.append(temp_file.name)
                            
                            for chunk in response.iter_content(chunk_size=8192):
                                temp_file.write(chunk)
                            temp_file.close()
                            
                            # Attach the downloaded file
                            with open(temp_file.name, 'rb') as file:
                                part = MIMEApplication(file.read(), Name=file_name)
                                part['Content-Disposition'] = f'attachment; filename="{file_name}"'
                                # Add Content-ID for potential HTML referencing
                                content_id = make_msgid()
                                part['Content-ID'] = content_id
                                msg.attach(part)
                        else:
                            print(f"Warning: Failed to download attachment from URL: {attachment}, status code: {response.status_code}")
                    except Exception as e:
                        print(f"Warning: Error downloading attachment from URL: {attachment}, error: {str(e)}")
                
                # Case 3: It's a base64 encoded file (format: "filename:base64content")
                elif isinstance(attachment, str) and ':' in attachment and ';base64,' in attachment.lower():
                    try:
                        # Parse the format "filename:data:image/jpeg;base64,/9j/4AAQSkZJRg..."
                        file_parts = attachment.split(':', 1)
                        file_name = file_parts[0]
                        base64_data = file_parts[1].split(';base64,', 1)[1]
                        
                        # Decode base64
                        file_data = base64.b64decode(base64_data)
                        
                        # Attach the file
                        part = MIMEApplication(file_data, Name=file_name)
                        part['Content-Disposition'] = f'attachment; filename="{file_name}"'
                        # Add Content-ID for potential HTML referencing
                        content_id = make_msgid()
                        part['Content-ID'] = content_id
                        msg.attach(part)
                    except Exception as e:
                        print(f"Warning: Error processing base64 attachment: {str(e)}")
                
                # Case 4: It's a directory - attach all files in the directory
                elif isinstance(attachment, str) and os.path.isdir(attachment):
                    for filename in os.listdir(attachment):
                        file_path = os.path.join(attachment, filename)
                        if os.path.isfile(file_path):
                            try:
                                with open(file_path, 'rb') as file:
                                    part = MIMEApplication(file.read(), Name=filename)
                                    part['Content-Disposition'] = f'attachment; filename="{filename}"'
                                    # Add Content-ID for potential HTML referencing
                                    content_id = make_msgid()
                                    part['Content-ID'] = content_id
                                    msg.attach(part)
                            except Exception as e:
                                print(f"Warning: Error attaching file {file_path}: {str(e)}")
                
                else:
                    print(f"Warning: Unrecognized attachment format: {attachment}")
        
        # Connect to SMTP server with proper connection handling
        attempt = 0
        max_attempts = 3
        success = False
        
        while attempt < max_attempts and not success:
            try:
                smtp_server = smtplib.SMTP_SSL('smtp.zoho.in', 465, timeout=30)
                
                # Login
                smtp_server.login(email_id, password)
                
                # Send email with proper timeouts
                smtp_server.sendmail(email_id, recipient_list, msg.as_string())
                smtp_server.quit()
                success = True
                
            except (socket.timeout, smtplib.SMTPServerDisconnected) as e:
                attempt += 1
                if attempt < max_attempts:
                    print(f"Connection issue. Retrying ({attempt}/{max_attempts})...")
                    time.sleep(2)
                else:
                    raise e
        
        # Clean up temp files
        for temp_file in temp_files:
            try:
                os.unlink(temp_file)
            except:
                pass
        
        return {
            "success": True,
            "message": f"Email sent successfully to To Address : {to_addresses} , CC Address : {cc_addresses} , Bcc Addresss : {bcc_addresses}"
        }
        
    except Exception as e:
        # Clean up temp files on error
        for temp_file in temp_files:
            try:
                os.unlink(temp_file)
            except:
                pass
            
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }

@mcp.tool()
def Mark_Email_Status(email_id, password, imap_id, status_type, folder="INBOX"):
    """
    Mark an email or multiple emails as read or unread based on message_id or imap_id

    Args:
        email_id: The exact sender's email address (also used for authentication) if not provided, the email_id don't execute ask for an user to provide the email_id
        password: The exact sender's password (also used for authentication) if not provided, the password don't execute ask for an user to provide the password
        status_type: "read" or "unread" to mark the email accordingly
        imap_id: Direct IMAP ID or list of IMAP IDs if available (skip searching if provided)
        folder: Email folder (default: "INBOX")
        
    Returns:
        bool: True if successful for all operations, False if any operation failed

    Note:
        - required parameters are not found in the arguments ask for an user to provide the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.
        - Can handle both single IMAP ID or a list of IMAP IDs.
        - if imap_id is not provided, call the Get_Emails_Zoho_Format tool to get the to fetch IMAP IDs
    """
    try:
        mail = imaplib.IMAP4_SSL("imap.zoho.in", 993)
        mail.login(email_id, password)
        
        # Select the folder with read-write access explicitly
        status_code, mailbox_info = mail.select(folder, readonly=False)
        
        if status_code != 'OK':
            print(f"Error selecting folder {folder}: {mailbox_info}")
            mail.logout()
            return False
        
        # Convert single imap_id to list for consistent handling
        imap_ids = imap_id
        if not isinstance(imap_ids, list):
            imap_ids = [imap_ids]
            
        print(f"Using IMAP ID: {imap_ids}")
        
        # Track overall success across all operations
        overall_success = True
        
        # Process each IMAP ID in the list
        for current_id in imap_ids:
            # Convert imap_id to string if it's a number
            if isinstance(current_id, int):
                current_id = str(current_id)
            
            # Check if email exists
            status_code, data = mail.fetch(current_id, "(FLAGS)")
            
            if status_code != 'OK':
                print(f"Email with IMAP ID {current_id} not found")
                overall_success = False
                continue
                
            # Fetch email content to extract from address
            status_code, msg_data = mail.fetch(current_id, "(RFC822)")
            if status_code == 'OK' and msg_data and msg_data[0]:
                email_msg = email.message_from_bytes(msg_data[0][1])
                from_address = email_msg.get('From', 'Unknown')
                print(f"From address: {from_address}")
            else:
                print("Could not retrieve email content to extract from address")
                
            # Get current flags for logging
            current_flags = data[0].decode() if data and data[0] else "Unknown"
            print(f"Current flags: {current_flags}")
            
            # Convert status_type to lowercase for consistent checking
            status_type_lower = status_type.lower()
            
            if status_type_lower == "read":
                print("Marking as read...")
                result, response = mail.store(current_id, '+FLAGS', '\\Seen')
            elif status_type_lower == "unread":
                print("Marking as unread...")
                result, response = mail.store(current_id, '-FLAGS', '\\Seen')
                
                # If the normal command fails, try alternate syntax
                if result != 'OK' or not response or not response[0]:
                    print("First attempt failed. Trying alternate command...")
                    result, response = mail.store(current_id, '-FLAGS.SILENT', '\\Seen')
            else:
                print(f"Invalid status_type: {status_type_lower}. Must be 'read' or 'unread'")
                overall_success = False
                continue
            
            if result != 'OK':
                print(f"Failed to set status: {result}, {response}")
                overall_success = False
                continue
                
            # Force commit changes
            mail.expunge()
            
            # Verify the change was applied
            status_code, data = mail.fetch(current_id, "(FLAGS)")
            
            if status_code != 'OK':
                print("Could not verify flag status")
                overall_success = False
                continue
                
            new_flags = data[0].decode() if data and data[0] else ""
            print(f"New flags: {new_flags}")
            
            # Check if our operation was successful
            is_read = "\\Seen" in new_flags
            success = (status_type_lower == "read" and is_read) or (status_type_lower == "unread" and not is_read)
            
            if success:
                print(f"SUCCESS: Email is now marked as {status_type_lower}")
            else:
                print(f"WARNING: Email flags do not reflect {status_type_lower} status")
                overall_success = False
        
        # Clean up
        mail.close()
        mail.logout()
        
        return overall_success
        
    except Exception as e:
        print(f"Error: {str(e)}")
        try:
            mail.close()
            mail.logout()
        except:
            pass
        return "Invalid Email of Password Please Verify it again"

@mcp.tool()
def Delete_Email(email_id, password, imap_id, folder="INBOX"):
    """
    Delete an email or multiple emails using the IMAP ID(s)
    
    Args:
        email_id: The exact sender's email address (also used for authentication) if not provided, the email_id don't execute ask for an user to provide the email_id
        password: The exact sender's password (also used for authentication) if not provided, the password don't execute ask for an user to provide the password
        imap_id: IMAP ID of the email to delete (can be a single ID or a list of IDs)
        folder: The folder containing the email
        
    Returns:
        dict: Status of the operation

    Note:
        - required parameters are not found in the arguments ask for an user to provide the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.
        - if imap_id is not provided, call the Get_Emails_Zoho_Format tool to get the to fetch IMAP IDs
    """
    try:
        # Convert single IMAP ID to list for consistent processing
        imap_ids = imap_id if isinstance(imap_id, list) else [imap_id]
        
        # Connect to IMAP server
        mail = imaplib.IMAP4_SSL("imap.zoho.in")
        mail.login(email_id, password)
        
        # Select folder
        status, mailbox_data = mail.select(folder)
        if status != 'OK':
            mail.logout()
            return {
                "success": False,
                "message": f"Failed to select folder {folder}: {status}"
            }
        
        # Get the number of messages in the mailbox
        total_messages = int(mailbox_data[0])
        
        # Track overall success
        overall_success = True
        deleted_ids = []
        failed_ids = []
        
        # Process each IMAP ID in the list
        for current_id in imap_ids:
            try:
                # Check if the IMAP ID is within valid range
                current_id = int(current_id)
                if current_id <= 0 or current_id > total_messages:
                    failed_ids.append(current_id)
                    overall_success = False
                    continue
            except ValueError:
                failed_ids.append(current_id)
                overall_success = False
                continue
            
            # Fetch the full email to extract the from address
            status_code, msg_data = mail.fetch(str(current_id), "(RFC822)")
            if status_code == 'OK' and msg_data and msg_data[0]:
                email_msg = email.message_from_bytes(msg_data[0][1])
                from_address = email_msg.get('From', 'Unknown')
                print(f"{current_id} - deleting email from address: {from_address}")
            else:
                print(f"{current_id} - could not retrieve email content to extract from address")
            
            # Try to fetch the message headers to verify it exists
            status, data = mail.fetch(str(current_id), '(BODY.PEEK[HEADER])')
            
            # Check if the response contains actual data
            if status != 'OK' or not data or len(data) < 1 or data[0] is None or (isinstance(data[0], tuple) and data[0][1] is None):
                failed_ids.append(current_id)
                overall_success = False
                print(f"{current_id} - there is not email")
                continue
            
            # Mark email for deletion
            status, data = mail.store(str(current_id), '+FLAGS', '\\Deleted')
            
            if status != 'OK':
                failed_ids.append(current_id)
                overall_success = False
                continue
            
            # Track successful deletion
            deleted_ids.append(current_id)
        
        # Permanently remove all marked emails
        if deleted_ids:  # Only expunge if we marked emails for deletion
            mail.expunge()
        
        # Close connection
        mail.close()
        mail.logout()
        
        # Generate appropriate return message based on results
        if not imap_ids:
            return {
                "success": False,
                "message": "No IMAP IDs provided for deletion"
            }
        elif len(imap_ids) == 1:
            if overall_success:
                return {
                    "success": True,
                    "message": f"Successfully deleted email with IMAP ID {imap_ids[0]}"
                }
            else:
                return {
                    "success": False,
                    "message": f"Failed to delete email with IMAP ID {imap_ids[0]}"
                }
        else:
            if overall_success:
                return {
                    "success": True,
                    "message": f"Successfully deleted {len(deleted_ids)} emails with IMAP IDs: {deleted_ids}"
                }
            elif deleted_ids:
                return {
                    "success": False,
                    "message": f"Partially succeeded: Deleted {len(deleted_ids)} emails with IMAP IDs: {deleted_ids}. Failed for IDs: {failed_ids}"
                }
            else:
                return {
                    "success": False,
                    "message": f"Failed to delete any emails. Failed for IDs: {failed_ids}"
                }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }


if __name__ == "__main__":
    # Get the port from environment variable (or use default)
    # Using a fixed host to avoid setting it each time
    port = int(os.getenv('PORT', 14145))

    print(f"Running server on 0.0.0.0:{port}")
    # Use the SSE transport with fixed host
    mcp.run(transport="sse", host="0.0.0.0", port=port)