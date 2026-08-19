# IMAP Mail Dispatcher

IMAP Mail Dispatcher is a small server-side mailbox processor that connects directly to an IMAP account and organizes incoming mail before or independently of desktop and mobile mail clients.

It does not relay mail and does not require SMTP. It works directly on folders already stored on the IMAP server.

## Features

- Moves unread messages to IMAP folders using YAML rules.
- Matches rules against the sender, subject, body, or subject + body.
- Supports exclusion rules.
- Inspects messages without intentionally marking them as read.
- Honors `X-Spam-Flag: YES` when present.
- Supports an optional local Bayesian spam classifier.
- Learns user corrections: when a message is moved out of `Junk` into a normal folder, its exact sender can be added to a persistent whitelist.
- Restores messages from whitelisted senders if another spam filter places them in `Junk` again.
- Keeps mailbox credentials out of the repository.

## Requirements

- Python 3
- An IMAP account with SSL support

Install the Python dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r app/requirements.txt
```

## Configuration

Create the local configuration files from the examples:

```bash
cp app/imap.yaml.example app/imap.yaml
cp app/rules.yaml.example app/rules.yaml
```

`imap.yaml` contains the mailbox connection settings:

```yaml
imap_server: imap.example.com
imap_port: 993
imap_user: user@example.com
imap_folder_inbox: INBOX
junk_folder: Junk
```

The password is intentionally not stored in this file.

The application reads a credential named `imap_password` from the directory specified by `CREDENTIALS_DIRECTORY`. This is compatible with credential managers such as systemd credentials.

Example layout:

```text
$CREDENTIALS_DIRECTORY/
└── imap_password
```

## Sorting rules

Rules are defined in `app/rules.yaml`. Each top-level key is the destination IMAP folder.

```yaml
Receipts:
  - subject: "invoice"
  - from: "@billing.example"

Security:
  - subject: "verification code"
  - subject: "newsletter"
    except: true
```

Supported match fields:

- `subject`
- `body`
- `subjectbody`
- `from`

Positive rules are alternatives: a message is moved when one of them matches. An `except: true` rule prevents the message from being moved to that folder when it matches.

Destination folders must already exist on the IMAP server.

## Spam handling

Spam decisions are applied in this order:

1. User whitelist
2. `X-Spam-Flag: YES`
3. Local Bayesian model, if a trained model is present

The whitelist is stored locally in `spam_whitelist.yaml` and is not intended to be committed to Git.

When the program observes a message leaving `Junk` and finds the same `Message-ID` in a normal IMAP folder, it treats that move as an explicit user correction and whitelists the exact sender address. It does not automatically whitelist the whole domain.

If a whitelisted sender later appears in `Junk`, the message is moved back to the inbox so normal sorting rules can process it.

## Running

Run one processing pass with:

```bash
CREDENTIALS_DIRECTORY=/path/to/credentials \
python app/imap_mail_dispatcher.py
```

Scheduling and service management are deliberately left outside this repository. The program can be launched by systemd, cron, a container scheduler, or any other mechanism appropriate for the host.

## Repository hygiene

Local mailbox configuration, learned spam data, logs, credentials, and host-specific deployment scripts are excluded through `.gitignore`.

Before publishing a fork, verify that no personal configuration or runtime data has been force-added to Git.

## License

Copyright (C) 2026 nicklausFR

GPL-3.0-or-later. See [LICENSE](LICENSE).
