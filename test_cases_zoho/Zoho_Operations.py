from fastmcp import FastMCP
import requests
from typing import Optional, List, Dict, Union
import json
from datetime import datetime, timezone
import random, string
import os
import imaplib
import argparse
import logging
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
import concurrent.futures
from bs4 import BeautifulSoup
import threading
from email.policy import default



# Create MCP instance

# Authentication management

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
        return "Refresh_Token_Parameter_Admin_Guide()"
   
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
            return Refresh_Token_Parameter_Admin_Guide()
    else:
        print("Error:", response.status_code, response.text)
        return Refresh_Token_Parameter_Admin_Guide()



# General Functionalities

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

def Get_All_User_Info(Access_Token_Generator) -> List[Dict[str, Union[str, float]]]:
    """
    Fetch all user accounts from Zoho Mail and return storage info per user.
    
    parameters:
        Access_Token_Generator: call the tool Access_Token_Generator to get the access token.
    
    return: 
        List of dictionaries containing user information and storage details.
    
    Note:
        - required parameters are not found in the arguments ask for an user to provide the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.

    """
    BASE_URL = "https://mail.zoho.in/api"
    HEADERS = {
        "Authorization": f"Zoho-oauthtoken {Access_Token_Generator}",
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


def Create_Zoho_Mail_User(Access_Token_Generator,firstName: str,zoid,domain,password=Generate_Custom_Password,lastName="") -> dict:
    """
    Creates a user in Zoho Mail with required fields and default values for optional fields.
    
    parameters:
        Access_Token_Generator: call the tool Access_Token_Generator to get the access token
        zoid: exact Zoho organization ID
        domain: exact domain name
        password: password for the user (if not provided, a custom password will be generated)
        firstName: first name of the user
        lastName(optional): last name of the user
    
    return: 
        Response dictionary from Zoho API
    
    Note:
        - required parameters are not found in the arguments ask for an user to provide the required parameters.
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
        "Authorization": f"Zoho-oauthtoken {Access_Token_Generator}",
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


def Update_IMAP_Status(Access_Token_Generator,zoid: str, account_id: str, zuid: str, enable_imap: bool) -> bool:
    """
    Updates the IMAP access status for a specific user account in a Zoho Mail organization.
    
    parameters:
        Access_Token_Generator: call the tool Access_Token_Generator to get the access token
        zoid: The exact organization ID (Zoid) of the Zoho Mail tenant.
        account_id: The exact account ID of the user whose IMAP status is being updated.
        zuid: The exact Zoho User ID (ZUID) of the target user.
        enable_imap: Set to True to enable IMAP, or False to disable it.
    
    return: 
        True if the IMAP status was updated successfully, False otherwise

    Note:
        - required parameters are not found in the arguments ask for an user to provide the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.
    """
    url = f"https://mail.zoho.in/api/organization/{zoid}/accounts/{account_id}"
    headers = {
        "Authorization": f"Zoho-oauthtoken {Access_Token_Generator}",
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


def Delete_User_By_ZUID(Access_Token_Generator, zoid, zuid: str):
    """
    Delete a Zoho Mail user using ZUID via the organization accounts API.

    parameters:
        Access_Token_Generator: call the tool Access_Token_Generator to get the access token
        zoid: exact organization ID (Zoid) of the Zoho Mail tenant
        zuid: exact Zoho User ID (ZUID) of the target user
    
    return: 
        True if the user was deleted successfully, False otherwise

    Note:
        - required parameters are not found in the arguments ask for an user to provide the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.
    """

    url = f"https://mail.zoho.in/api/organization/{zoid}/accounts"
    
    headers = {
        "Authorization": f"Zoho-oauthtoken {Access_Token_Generator}",
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


def Reset_Zoho_Mail_Password(Access_Token_Generator, zoid, zuid, new_password) -> bool:
    """
    Reset the password for a specific user account in a Zoho Mail organization.

    parameters:
        Access_Token_Generator: call the tool Access_Token_Generator to get the access token
        zoid: exact organization ID (Zoid) of the Zoho Mail tenant
        zuid: exact Zoho User ID (ZUID) of the target user
        new_password: new password for the user if not provided, a custom password will be generated
    return: 
        True if the password was reset successfully, False otherwise

    Note:
        required parameters are not found in the arguments ask for an user to provide the required parameters
    """
    url = f"https://mail.zoho.in/api/organization/{zoid}/accounts/{zuid}"
    
    headers = {
        "Authorization": f"Zoho-oauthtoken {Access_Token_Generator}",
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
def Get_Emails_Zoho_Format(email_id, password, status_type="All", folder="INBOX", max_emails=1000, 
                            batch_size=1000, max_workers=8, attachment_required=False, filters=None, connection_retries=2, 
                            start_date=None, end_date=None):


    """
    Get Emails Zoho Format

    Fetches emails from a Zoho Mail account using the IMAP4 protocol in a structured and optimized format.

    Args:
        email_id (str): The exact email address of the user (used for login and filtering).
            - This value should be the exact address provided by the user, with no internal inference or guessing.
            - If not provided, attempt to extract using Get_All_User_Info; if still not found, prompt the user.

        password (str): The exact password for the given email_id.
            - This value must be provided by the user if email_id is known and should be taken as-is.

        status_type (str): The user-provided status of emails to retrieve.
            - Accepts values like "Read", "Unread", "All", or similar nearby terms (e.g., "Seen", "Unseen", "Opened").
            - The system interprets these values to determine whether to fetch read, unread, or all emails.

        folder (str): The exact folder name in the mailbox to search emails from.
            - Default is "INBOX".
            - This value should be taken exactly as provided by the user.

        max_emails (int): Maximum number of emails to fetch.
            - Takes the exact number provided by the user. Default is 1000.

        batch_size (int): Number of emails to fetch in each batch.
            - Takes the exact number provided by the user. Default is 1000.

        max_workers (int): Number of parallel threads to use for processing emails.
            - Takes the exact value provided by the user. Default is 8.

        attachment_required (bool): Whether to fetch email attachment metadata.
            - If True, the function will parse and return attachment information.
            - Defaults to False unless filters or date ranges are used.

        filters (list or str): Keywords to match against email content.
            - Filters must be exact user-provided keywords.
            - Each keyword is matched using OR logic across FROM, SUBJECT, and BODY fields.
            - If any match is found in any of these fields, the email is selected.

        connection_retries (int): Number of retry attempts in case of connection failure.
            - Takes the exact integer value provided by the user. Default is 2.

        start_date (str): Exact start date in 'YYYY-MM-DD' format.
            - Emails from this date (inclusive) will be fetched.
            - If not provided, no lower date bound is applied.

        end_date (str): Exact end date in 'YYYY-MM-DD' format.
            - Emails up to this date (exclusive) will be fetched.
            - Defaults to the current date if not provided.

    Returns:
        List[Dict]: A list of dictionaries, each containing structured email data.

        Each dictionary contains the following fields:
            - imapId: Unique IMAP ID of the email.
            - status: "1" if the email is read, "0" if unread.
            - subject: Decoded subject line of the email.
            - fromName: Name of the sender (if available).
            - fromAddress: Sender's email address.
            - toAddress: Recipient email addresses.
            - receivedDate: Original received date from headers.
            - UTC_Received_time: Received date converted to UTC format.
            - hasAttachment: "1" if attachments are present, "0" otherwise.
            - attachments: List of attachment metadata (filenames).
            - body content: Cleaned body content from plain text or HTML.

    Notes:
        - All values passed to this function are treated as **exact inputs from the user**, unless explicitly inferred (like status_type variants).
        - If required parameters are missing, attempt to retrieve them using Get_All_User_Info.
        - If any time fields are found in the response, call encode_time to convert them to UTC datetime strings.
        - Attachment parsing is triggered automatically if filters or date ranges are used.
        - **Keyword filtering** uses **OR logic** across FROM, SUBJECT, and BODY fields.
            - For example: if one keyword is present in the subject and another in the body, only one match is needed for the email to be included.
        - **Date filtering is applied first**, using `SINCE` and `BEFORE` criteria on the mail server.
        - Emails are processed in **batches** and with **multithreading** for performance optimization.
        - If any **timeout or failure** occurs during execution, the function will **continue from the current point**, not restart from the beginning.
        - IMAP connection is attempted via both `imap.zoho.in` and `imap.zoho.com` for reliability.
        - In case of a failure to retrieve emails — whether due to connection issues, invalid filters, or even after fetching all available emails with no matches — the user will be **prompted to provide one or more keywords** that may appear in:
            - The subject line  
            - The email body  
            - The sender's email address (From)
    """

    # Set end_date to current date if not provided
    
    if end_date is None:
        end_date = datetime.now().strftime('%Y-%m-%d')
    
    # Convert the dates into the proper format (dd-MMM-yyyy)
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d').strftime('%d-%b-%Y')
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d').strftime('%d-%b-%Y')
    
    if start_date and end_date:
        attachment_required = True

    

    # Define regex for parsing the from address
    from_re = re.compile(r'(.*?)\s*<([^>]+)>')

    def extract_body_content_from_item(item):
        """
        Extracts the body content from an email message (either plain text or HTML) using the item data.
        
        Parameters:
            item (tuple): A tuple containing raw email data (msg_data).
            
        Returns:
            str: The body content of the email.
        """
        body_content = ""

        try:
            # Parse the email data
            raw_num, msg_data, flags = item
            msg = email.message_from_bytes(msg_data, policy=default)

            # Traverse through all parts of the email
            for part in msg.iter_parts():
                # Check if the part is plain text or HTML text
                content_type = part.get_content_type()
                
                # Handle text/plain part (Plain text body)
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        body_content += payload.decode(charset, errors="replace").strip() + "\n"
                    except Exception as e:
                        print(f"Error decoding plain text body: {e}")
                
                # Handle text/html part (HTML body)
                elif content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        html_content = payload.decode(charset, errors="replace")
                        
                        # If body_content is empty, use the HTML body
                        if not body_content:
                            soup = BeautifulSoup(html_content, "html.parser")
                            body_content = soup.get_text(separator="\n", strip=True)
                    except Exception as e:
                        print(f"Error decoding HTML body: {e}")
        
        except Exception as e:
            print(f"Error processing email item: {e}")
        
        return body_content.strip()


    def decode_subject(subject):
        """Decode the email subject"""
        if not subject:
            return ""
        try:
            decoded = decode_header(subject)
            return ''.join([part.decode(charset or 'utf-8', errors='replace') if isinstance(part, bytes) else str(part)
                            for part, charset in decoded])
        except Exception:
            return subject


    # Set attachment_required to True if filters are provided
    if filters is not None:
        attachment_required = True
        
    # Convert filters to list if it's a string
    if filters and isinstance(filters, str):
        filters = [filters]
    
    # Performance optimization: Use a faster path when no attachments or filters are required
    use_fast_path = not attachment_required and not filters

    try:
        # Connect to the IMAP server with retry logic
        mail = None
        retry_count = 0
        connection_timeout = 10  # 10 second timeout for connection attempts
        
        try:
            # First attempt to login with imap.zoho.in
            mail = imaplib.IMAP4_SSL("imap.zoho.in", timeout=connection_timeout)
            mail.login(email_id, password)
            mail.select(folder, readonly=True)
            print("Login successful with imap.zoho.in")
        except imaplib.IMAP4.error as e:
            print(f"Failed to connect to IMAP server imap.zoho.in : {e}")
            print("Trying imap.zoho.com...")
            try:
                # Second attempt to login with imap.zoho.com
                mail = imaplib.IMAP4_SSL("imap.zoho.com", timeout=connection_timeout)
                mail.login(email_id, password)
                mail.select(folder, readonly=True)
                print("Login successful with imap.zoho.com")
            except imaplib.IMAP4.error as e:
                print(f"Failed to connect to IMAP server imap.zoho.com : {e}")
                return "Invalid credentials"

        # Base search criteria based on status_type
        search_criteria = "ALL"
        if status_type.upper() == "READ":
            search_criteria = "SEEN"
        elif status_type.upper() == "UNREAD":
            search_criteria = "UNSEEN"

        # Apply server-side filtering if filters provided
        if filters:
            combined_filters = []
            for keyword in filters:
                # Search in FROM, SUBJECT, and BODY
                combined_filters.append(f'(OR (FROM "{keyword}") (OR (SUBJECT "{keyword}") (BODY "{keyword}")))')
            
            if combined_filters:
                combined_search = " OR ".join(combined_filters)
                search_criteria = f"({search_criteria}) ({combined_search})"
        
        # Filter by date range if start_date and end_date are provided
        if start_date and end_date:
            search_criteria = f"({search_criteria}) (SINCE {start_date}) (BEFORE {end_date})"

        status_code, search_data = mail.search(None, search_criteria)
        if status_code != 'OK':
            mail.logout()
            return "Failed to search emails"

        # Get all message IDs that match the search criteria
        message_ids = []
        if search_data and search_data[0]:
            message_ids = search_data[0].split()

        if not message_ids:
            if filters:
                filter_list = ', '.join(filters) if isinstance(filters, list) else filters
                return f"No data found for the provided keyword(s): {filter_list}."
            return []

        # Sort by most recent first and limit to max_emails if specified
        message_ids = message_ids[::-1]  # Reverse to get newest first
        if max_emails and len(message_ids) > max_emails:
            message_ids = message_ids[:max_emails]

        emails = []
        batches = [message_ids[i:i+batch_size] for i in range(0, len(message_ids), batch_size)]
        
        for batch_num, batch in enumerate(batches):
            # Build a comma-separated list of IDs to fetch
            id_set = ",".join(id.decode() if isinstance(id, bytes) else str(id) for id in batch)
            
            # Use a more efficient fetch command when attachments aren't needed
            fetch_command = "(BODY.PEEK[] FLAGS)" if attachment_required or filters else "(RFC822.HEADER FLAGS)"
            
            status, data = mail.fetch(id_set, fetch_command)
            if status != "OK":
                continue

            items = []
            for i in range(0, len(data), 2):
                if i + 1 < len(data) and isinstance(data[i], tuple):
                    raw_num, msg_data = data[i]
                    # Extract flags
                    flag_data = raw_num.decode() if isinstance(raw_num, bytes) else str(raw_num)
                    flags_match = re.search(r'FLAGS \((.*?)\)', flag_data)
                    flags = flags_match.group(1) if flags_match else ""
                    items.append((raw_num, msg_data, flags))

            # Define processing functions
            def process_email(item):
                """Process emails and return structured data"""
                try:
                    raw_num, msg_data, flags = item
                    imap_id = raw_num.decode().split()[0] if isinstance(raw_num, bytes) else raw_num.split()[0]
                    msg = email.message_from_bytes(msg_data)
                    
                    # Decode the subject dynamically
                    subject = decode_subject(msg.get('Subject', ''))
                    from_addr = msg.get('From', '')
                    to_addr = msg.get('To', '')
                    cc_addr = msg.get('Cc', '') or msg.get('CC', '')
                    date = msg.get('Date', '')
                    message_id = msg.get('Message-ID', '')
                    is_read = '1' if '\\Seen' in flags else '0'
                    
                    # Parse UTC time
                    try:
                        UTC_Received_time = datetime.strptime(
                            date, '%a, %d %b %Y %H:%M:%S %z'
                        ).astimezone(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S %z')
                    except Exception:
                        UTC_Received_time = date
                    
                    # Parse from address
                    from_match = from_re.match(from_addr)
                    from_name = from_match.group(1).strip() if from_match else ''
                    from_email = from_match.group(2).strip() if from_match else from_addr.strip()

                    # Fetch body content dynamically
                    body_content = extract_body_content_from_item(item)

                    # Check for attachments
                    has_attachment = "0"
                    attachment_data = []
                    attachment_count = 0
                    if attachment_required:
                        for part in msg.walk():
                            content_disposition = str(part.get("Content-Disposition", "")).lower()
                            if "attachment" in content_disposition:
                                has_attachment = "1"
                                filename = part.get_filename()
                                if filename:
                                    attachment_data.append({"filename": filename})
                                    attachment_count += 1
                    
                    # Prepare the result object
                    email_obj = {
                        "imapId": imap_id,
                        "status": is_read,
                        "subject": subject,
                        "fromName": from_name,
                        "fromAddress": from_email,
                        "toAddress": to_addr,
                        "receivedDate": date,
                        "UTC_Received_time": UTC_Received_time,
                    }

                    if attachment_required:
                        email_obj["attachments"] = attachment_data
                        email_obj["totalAttachments"] = attachment_count
                        email_obj["body content"] = body_content
                        email_obj["hasAttachment"] = has_attachment

                    return email_obj
                except Exception as e:
                    return None

            # Process emails in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                results = list(executor.map(process_email, items))
                filtered_results = [r for r in results if r]
                emails.extend(filtered_results)
        
        # Logout from the server
        mail.close()
        mail.logout()
        
        return emails

    except Exception as e:
        print(f"Error in Get_Emails_Zoho_Format: {e}")
        try:
            mail.close()
            mail.logout()
        except:
            pass
        return []


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


def Mark_Email_Status(email_id, password, imap_id, status_type, folder="INBOX"):
    """
    Mark an email as read or unread based on message_id or imap_id

    Args:
        email_id: The exact sender's email address (also used for authentication) if not provided, the email_id don't execute ask for an user to provide the email_id
        password: The exact sender's password (also used for authentication) if not provided, the password don't execute ask for an user to provide the password
        status_type: "read" or "unread" to mark the email accordingly
        imap_id: Direct IMAP ID if available (skip searching if provided)
        folder: Email folder (default: "INBOX")
        
    Returns:
        bool: True if successful, False otherwise

    Note:
        - required parameters are not found in the arguments ask for an user to provide the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.
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
            
        found_imap_id = imap_id
        
        # Convert imap_id to string if it's a number
        if isinstance(found_imap_id, int):
            found_imap_id = str(found_imap_id)
        
        print(f"Using IMAP ID: {found_imap_id}")
        
        # Check if email exists
        status_code, data = mail.fetch(found_imap_id, "(FLAGS)")
        
        if status_code != 'OK':
            print(f"Email with IMAP ID {found_imap_id} not found")
            mail.close()
            mail.logout()
            return False
            
        # Get current flags for logging
        current_flags = data[0].decode() if data and data[0] else "Unknown"
        print(f"Current flags: {current_flags}")
        
        # Convert status_type to lowercase for consistent checking
        status_type = status_type.lower()
        
        if status_type == "read":
            print("Marking as read...")
            result, response = mail.store(found_imap_id, '+FLAGS', '\\Seen')
        elif status_type == "unread":
            print("Marking as unread...")
            result, response = mail.store(found_imap_id, '-FLAGS', '\\Seen')
            
            # If the normal command fails, try alternate syntax
            if result != 'OK' or not response or not response[0]:
                print("First attempt failed. Trying alternate command...")
                result, response = mail.store(found_imap_id, '-FLAGS.SILENT', '\\Seen')
        else:
            print(f"Invalid status_type: {status_type}. Must be 'read' or 'unread'")
            mail.close()
            mail.logout()
            return False
        
        if result != 'OK':
            print(f"Failed to set status: {result}, {response}")
            mail.close()
            mail.logout()
            return False
            
        # Force commit changes
        mail.expunge()
        
        # Re-select folder to refresh server state
        mail.close()
        mail.select(folder)
        
        # Verify the change was applied
        status_code, data = mail.fetch(found_imap_id, "(FLAGS)")
        
        if status_code != 'OK':
            print("Could not verify flag status")
            mail.close()
            mail.logout()
            return False
            
        new_flags = data[0].decode() if data and data[0] else ""
        print(f"New flags: {new_flags}")
        
        # Check if our operation was successful
        is_read = "\\Seen" in new_flags
        success = (status_type == "read" and is_read) or (status_type == "unread" and not is_read)
        
        if success:
            print(f"SUCCESS: Email is now marked as {status_type}")
        else:
            print(f"WARNING: Email flags do not reflect {status_type} status")
        
        # Clean up
        mail.close()
        mail.logout()
        
        return success
        
    except Exception as e:
        print(f"Error: {str(e)}")
        try:
            mail.close()
            mail.logout()
        except:
            pass
        return False


def Delete_Email(email_id, password, imap_id, folder="INBOX"):
    """
    Delete an email using the IMAP ID
    
    Args:
        email_id: The exact sender's email address (also used for authentication) if not provided, the email_id don't execute ask for an user to provide the email_id
        password: The exact sender's password (also used for authentication) if not provided, the password don't execute ask for an user to provide the password
        imap_id: IMAP ID of the email to delete
        folder: The folder containing the email
        
    Returns:
        dict: Status of the operation

    Note:
        - required parameters are not found in the arguments ask for an user to provide the required parameters.
        - If any time field is found in response call the encode_time tool to convert it to UTC datetime string.
    """
    try:
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
        
        # Check if the IMAP ID is within valid range
        try:
            imap_id = int(imap_id)
            if imap_id <= 0 or imap_id > total_messages:
                mail.close()
                mail.logout()
                return {
                    "success": False,
                    "message": f"Invalid IMAP ID: {imap_id}. Valid range is 1-{total_messages}"
                }
        except ValueError:
            mail.close()
            mail.logout()
            return {
                "success": False,
                "message": f"Invalid IMAP ID format: {imap_id}. Must be a positive integer."
            }
        
        # Try to fetch the message headers to verify it exists
        status, data = mail.fetch(str(imap_id), '(BODY.PEEK[HEADER])')
        
        # Check if the response contains actual data
        if status != 'OK' or not data or len(data) < 1 or data[0] is None or (isinstance(data[0], tuple) and data[0][1] is None):
            mail.close()
            mail.logout()
            return {
                "success": False,
                "message": f"Email with IMAP ID {imap_id} not found"
            }
        
        # Mark email for deletion
        status, data = mail.store(str(imap_id), '+FLAGS', '\\Deleted')
        
        if status != 'OK':
            mail.close()
            mail.logout()
            return {
                "success": False,
                "message": f"Failed to mark email for deletion: {status}"
            }
        
        # Permanently remove
        mail.expunge()
        
        # Close connection
        mail.close()
        mail.logout()
        
        return {
            "success": True,
            "message": f"Successfully deleted email with IMAP ID {imap_id}"
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }


# if __name__ == "__main__":
#     # Get the port from environment variable (or use default)
#     # Using a fixed host to avoid setting it each time
#     port = int(os.getenv('PORT', 14145))

#     print(f"Running server on 0.0.0.0:{port}")
#     # Use the SSE transport with fixed host
#     mcp.run(transport="sse", host="0.0.0.0", port=port)