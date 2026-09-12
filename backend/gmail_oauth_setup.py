"""One-time interactive OAuth grant for Gmail API access to a specific mailbox.

Run this once from `backend/`: `python gmail_oauth_setup.py`. It opens your default
browser, asks you to log into the Gmail account you want to monitor and approve
read-only access, then saves a refresh token to gmail_token.json (gitignored) --
the backend uses that token afterwards without repeating this login.

Requires gmail_oauth_client.json (the Desktop-app OAuth client downloaded from
Google Cloud Console; gitignored, never commit it).
"""
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# Read-only is sufficient: users.watch() + users.history.list() + users.messages.get()
# all work under this scope. No send/modify/delete access is requested.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
# Deliberately always local (not gmail_integration.TOKEN_FILE / GMAIL_TOKEN_FILE):
# this script needs an interactive browser login, which only ever happens on your
# own machine, never on a deployed server -- its output gets manually copied into
# Render's Secret Files afterward, it doesn't write there directly.
CLIENT_SECRETS_FILE = Path(__file__).parent / 'gmail_oauth_client.json'
TOKEN_FILE = Path(__file__).parent / 'gmail_token.json'


def main():
    if not CLIENT_SECRETS_FILE.exists():
        raise SystemExit(f'{CLIENT_SECRETS_FILE} not found. Download the Desktop app '
                          'OAuth client JSON from Google Cloud Console and save it there.')

    creds = None
    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(str(CLIENT_SECRETS_FILE), SCOPES)
        print('Opening your browser -- log in with the Gmail account you want to monitor '
              'and approve read-only access.')
        creds = flow.run_local_server(port=0)

    TOKEN_FILE.write_text(creds.to_json())
    print(f'Saved token to {TOKEN_FILE}. This account can now be watched for new mail.')


if __name__ == '__main__':
    main()
