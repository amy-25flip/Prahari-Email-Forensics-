"""One-time (well, ~every 7 days -- Gmail expires watch registrations) call to start
push notifications for the mailbox authorized via gmail_oauth_setup.py.

Usage: python gmail_watch_start.py <pubsub-topic-name>
  e.g. python gmail_watch_start.py projects/email-threat-detection-508403/topics/gmail-notifications
"""
import sys

import gmail_integration


def main():
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python gmail_watch_start.py projects/<project>/topics/<topic>')
    response = gmail_integration.start_watch(sys.argv[1])
    print(f"Watching. historyId={response['historyId']} expiration={response['expiration']} (ms since epoch)")


if __name__ == '__main__':
    main()
