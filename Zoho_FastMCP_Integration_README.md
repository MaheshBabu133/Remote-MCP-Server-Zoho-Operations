
# Zoho Mail Integration with FastMCP

This project integrates Zoho Mail API functionalities with FastMCP to perform operations such as generating access tokens, managing email settings, creating users, and more. The setup includes Python virtual environments and bash scripts for ease of deployment and operation.

## Table of Contents

- [Zoho OAuth Authentication Flow](#zoho-oauth-authentication-flow)
- [Setup](#setup)
- [Installation and Running the MCP Server](#installation-and-running-the-mcp-server)
- [Tools Usage](#tools-usage)
- [License](#license)
- [Limitations](#limitations)

## Zoho OAuth Authentication Flow

1. **Generate Authorization Code**:
   - Navigate to the [Zoho API console](https://api-console.zoho.in/) and create a self-client application.
   - Request the **authorization code** by specifying the required scopes and duration.
   - This code should be used to get the refresh token.

2. **Exchange Authorization Code for Refresh Token**:
   - Use the authorization code to exchange it for a **refresh token** by using the `Refresh_Token_Generator` tool.
   - The refresh token is stored in a `token.txt` file for future use.

3. **Generate Access Token**:
   - Use the stored refresh token to generate an **access token** using the `Access_Token_Generator` tool.
   - This access token is used for all API calls to Zoho Mail.




## Setup

### 1. Generate Zoho OAuth Tokens

To interact with Zoho's API, you need an access token and refresh token. Follow these steps:


1. **Register a Self-Client Application**:
   - Go to Zoho Developer Console (https://api-console.zoho.com)
   - Create a new self-client application
   - Click on the Client Secret button
   - Note your CLIENT_ID and CLIENT_SECRET from the configuration

2. **Generate an Authorization Code**:
   - Click on the Generate Code button
   - For the Scope value, enter: `ZohoMail.messages.ALL,ZohoMail.organization.accounts.ALL,ZohoMail.organization.accounts.UPDATE,ZohoMail.folders.READ`
   - Set time duration based on your requirement (Suggested: 10 min)
   - Scope Description: `Zoho email and account operations`
   - Click on the create button
   - Copy the generated authorization code

3. **Generate a Refresh Token**:
   - Use the `Refresh_Token_Generator` tool with the following parameters:
     - CLIENT_ID: your client ID
     - CLIENT_SECRET: your client secret
     - authorization_code: the authorization code you received
     - REDIRECT_URI: the redirect URI you registered (default: http://localhost:8000/callback)

**Note**: 
- The authorization code is valid for a limited time (usually 10 minutes). You need to generate the refresh token before it expires.
- Generating a refresh token is a one-time operation.


## Installation and Running the MCP Server 

You can run the MCP server using the `manage.sh` script, which sets up the environment and starts the FastMCP server. To do this:

1. Open a terminal and navigate to the project directory.
2. Use one of the following commands to manage the server:

```bash
# Start the server in background mode (no logs displayed)
./manage.sh start <port number>

# Start the server with debug logs displayed in the terminal
./manage.sh start -d <port number>

# Check the server status
./manage.sh status <port number>

# Stop the server
./manage.sh stop <port number>
```

This script performs the following actions:
- Navigates to the project directory
- Kills any running instances of `fast_mcp.py` before starting
- Creates a virtual environment (if it doesn't exist)
- Installs required dependencies
- Runs the `fast_mcp.py` script with the proper environment settings

**Note**: 
- When using `start` without the `-d` flag, the server runs in the background and you can continue using the terminal.
- When using `start -d`, the server runs in the foreground with logs displayed directly in the terminal. You'll need to press Ctrl+C to stop it.
- The `stop` command gracefully terminates the server process.

Once the server is running, you can access the services exposed by FastMCP.


## Tools Usage

### Authentication Management
#### Refresh Token Parameter Admin Guide
- Provides a comprehensive step-by-step guide for generating a refresh token for the Zoho Mail API.
- returns: Refresh token guide as a string 
```bash
# Generate a refresh token
refresh_token = Refresh_Token_Parameter_Admin_Guide()
```

#### Refresh Token Generator
- Generates and stores a Zoho OAuth refresh token using the authorization code flow.
- returns: Refresh token as a string if successful

```bash
# Generate a refresh token
refresh_token = Refresh_Token_Generator(
    CLIENT_ID="your_client_id",
    CLIENT_SECRET="your_client_secret",
    authorization_code="your_authorization_code"
)

```


#### Access Token Generator
- Generates an access token for Zoho API using the stored refresh token.
- returns: Access token as a string if successful

```bash
# Generate an access token
access_token = Access_Token_Generator()
```



### Utility Functions

#### encode_time(timestamp_ms)
- Converts a timestamp in milliseconds to a UTC datetime string.
- returns: UTC datetime string

```python
# Convert a timestamp to a datetime string
datetime_str = encode_time("timestamp_ms")
```

#### Generate_Custom_Password()
- Generates a custom password with a specific structure.
- returns: Generated custom password with the format: [Uppercase letter][3 lowercase letters][@][3 digits]

```python 
# Generate a custom password
custom_password = Generate_Custom_Password()
```


### User Management

#### All User Information
- Fetches all user accounts from Zoho Mail and returns storage info per user.
- returns: List of dictionaries containing user information and storage details

```python
# Get all user information
users = Get_All_User_Info(Access_Token_Generator())
```

#### User Creation
- Creates a user in Zoho Mail with required fields and default values for optional fields.
- returns: Response dictionary from Zoho API with user details if successful or error message if failed

```python
# Create a new user
new_user = Create_Zoho_Mail_User(
    access_token_generator=Access_Token_Generator(),
    firstName="Your Name",
    zoid="your_organization_id",
    domain="yourdomain",
    password="your_password",
    lastName="Doe" # Optional
)
```

#### Update IMAP Status
- Updates the IMAP access status for a specific user account in a Zoho Mail organization.
- returns: True if the IMAP status was updated successfully, False otherwise

```python
# Update IMAP status
result = Update_IMAP_Status(
    access_token_generator=Access_Token_Generator(),
    zoid="your_organization_id",
    account_id="your_account_id",
    zuid="your_zuid",
    enable_imap=True # Optional Enable IMAP is True otherwise False i.e disable IMAP
)
```

#### Delete an User
- Deletes a Zoho Mail user using ZUID via the organization accounts API.
- returns: True if the user was deleted successfully, False otherwise

```python
# Delete a user by ZUID
result = Delete_User_By_ZUID(
    access_token_generator=Access_Token_Generator(),
    zoid="your_organization_id",
    zuid="your_zuid"
)
```

#### Reset Zoho Mail Password
- Resets the password for a specific user account in a Zoho Mail organization.
- returns: True if the password was reset successfully, False otherwise

```python
# Reset user password
result = Reset_Zoho_Mail_Password(
    access_token_generator=Access_Token_Generator(),
    zoid="your_organization_id",
    zuid="your_zuid",
    new_password="your_new_password" # Optional if password is not provided by user custom password will be generated
)
```

### Email Management

#### All Emails Information of a User
- Retrieves all emails from a Zoho Mail account using the specified IMAP ID.
- returns: Email details if successful, None otherwise

```python
# Get all emails
get_emails_zoho_format(email_id, 
password, 
status_type = "All",  # Optional "All", "Unread", "Read" default "All"
folder="INBOX") # Optional "INBOX", "Sent", "Drafts", "Trash", "Junk", "Outbox" default "INBOX"
```

#### Send an Email
- Sends an email from a Zoho Mail account using the specified sender credentials.
- returns: True if the email was sent successfully, False otherwise

```python
# Send an email
result = Send_Zoho_Email(
    email_id="sender_email@domain.com",
    password="sender_password",
    to_addresses=["recipient@example.com"], # List of recipient email addresses or string of single recipient
    subject="Test Email",
    body="This is a test email."
    cc="cc_email@example.com", # Optional List of CC email addresses or string of single CC recipient
    bcc="bcc_email@example.com" # Optional List of BCC email addresses or string of single BCC recipient
)
```


#### Mark Email Status
- Marks an email as read or unread based on the IMAP ID.
- returns: True if the email status was updated successfully, False otherwise

```python
# Mark an email as read
result = Mark_Email_Status(
    email_id="sender_email@domain.com",
    password="sender_password",
    imap_id="list of email_imap_ids",
    status_type="read" # Optional "read" or "unread"
)
```

#### Delete an Email
- Deletes an email using the IMAP ID.
- returns: True if the email was deleted successfully, False otherwise

```python
# Delete an email
result = Delete_Email(
    email_id="sender_email@domain.com",
    password="sender_password",
    imap_id="list of email_imap_ids"
)
```


## Limitations
- When the email load is heavy, the user should wait for some time before making the next API call
- When creating a user, the username should not contain any special characters or spaces.
- When a user resets their password, the old password and new password should be different.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.



This README provides a comprehensive overview of setting up and using the Zoho Mail integration with FastMCP, including the OAuth authentication flow, installation steps, and running the server. Let me know if you need further clarifications!
