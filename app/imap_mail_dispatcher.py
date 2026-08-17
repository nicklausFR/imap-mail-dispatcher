import imaplib
import os
import email
import yaml
import spam_filter
from email.header import decode_header
import re
from pathlib import Path

def decode_subject(subject):
    if not subject:
        return ""
    decoded_fragments = decode_header(subject)
    decoded_string = ""
    for fragment, encoding in decoded_fragments:
        if isinstance(fragment, bytes):
            try:
                decoded_string += fragment.decode(encoding or 'utf-8', errors='ignore')
            except:
                decoded_string += fragment.decode(errors='ignore')
        else:
            decoded_string += fragment
    return decoded_string

# Les fichiers de configuration sont toujours pris à côté du programme.
APP_DIR = Path(__file__).resolve().parent

# Charger la configuration IMAP
with open(APP_DIR / 'imap.yaml', 'r') as f:
    imap_config = yaml.safe_load(f)

# Charger les règles de tri
with open(APP_DIR / 'rules.yaml', 'r') as f:
    rules_yaml = yaml.safe_load(f)

# Connexion au serveur IMAP
imap = imaplib.IMAP4_SSL(imap_config['imap_server'], imap_config['imap_port'])
credential_dir = os.environ.get('CREDENTIALS_DIRECTORY')
if not credential_dir:
    raise RuntimeError('CREDENTIALS_DIRECTORY is not set')
credential_file = Path(credential_dir) / 'imap_password'
imap_password = credential_file.read_text(encoding='utf-8')
imap.login(imap_config['imap_user'], imap_password)
del imap_password

# Observer Junk même lorsqu'il n'y a aucun nouveau mail. Si un message qui
# était dans Junk est remis dans INBOX, son expéditeur exact devient une
# correction utilisateur persistante (whitelist).
try:
    spam_filter.learn_user_corrections(imap, imap_config)
except Exception as exc:
    # Le suivi de whitelist ne doit jamais bloquer le tri normal.
    print(f"[SPAM FILTER] Suivi des corrections impossible: {exc}")

# Faire respecter la whitelist même lorsqu'un autre antispam/client déplace
# le message directement dans Junk avant que imap-mail-dispatcher ne voie INBOX.
try:
    spam_filter.rescue_whitelisted_from_junk(imap, imap_config)
except Exception as exc:
    print(f"[SPAM FILTER] Application de la whitelist dans Junk impossible: {exc}")

imap.select(imap_config['imap_folder_inbox'])

# Vérifier s'il y a des mails non lus
status, messages = imap.search(None, 'UNSEEN')
if status != 'OK' or not messages[0]:
    print("Rien à traiter.")
    imap.logout()
    exit(0)

mails_moved = 0

for num in messages[0].split():
    status, data = imap.fetch(num, '(BODY.PEEK[])')
    if status != 'OK':
        continue

    msg = email.message_from_bytes(data[0][1])
    subject = decode_subject(msg.get('Subject', ''))
    from_email = email.utils.parseaddr(msg.get('From'))[1]
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode(errors='ignore')
                except:
                    continue
    else:
        try:
            body += msg.get_payload(decode=True).decode(errors='ignore')
        except:
            pass

    moved = False

    for folder, rules in rules_yaml.items():
        positives = []
        negatives = []

        for rule in rules:
            if isinstance(rule, dict):
                if 'subject' in rule:
                    entry = {'zone': 'subject', 'keyword': rule['subject']}
                elif 'body' in rule:
                    entry = {'zone': 'body', 'keyword': rule['body']}
                elif 'subjectbody' in rule:
                    entry = {'zone': 'subjectbody', 'keyword': rule['subjectbody']}
                elif 'from' in rule:
                    entry = {'zone': 'from', 'keyword': rule['from']}
                else:
                    continue

                if rule.get('except', False):
                    negatives.append(entry)
                else:
                    positives.append(entry)

        excluded = False
        for neg in negatives:
            zone = neg['zone']
            keyword = neg['keyword']
            if zone == 'subject':
                target_text = subject
                matched = re.search(re.escape(keyword), target_text, re.IGNORECASE)
            elif zone == 'body':
                target_text = body
                matched = re.search(re.escape(keyword), target_text, re.IGNORECASE)
            elif zone == 'subjectbody':
                target_text = subject + " " + body
                matched = re.search(re.escape(keyword), target_text, re.IGNORECASE)
            elif zone == 'from':
                target_text = from_email
                matched = target_text.lower().endswith(keyword.lower())
            else:
                continue

            if matched:
                excluded = True
                break
        if excluded:
            continue

        for pos in positives:
            zone = pos['zone']
            keyword = pos['keyword']
            if zone == 'subject':
                target_text = subject
                matched = re.search(re.escape(keyword), target_text, re.IGNORECASE)
            elif zone == 'body':
                target_text = body
                matched = re.search(re.escape(keyword), target_text, re.IGNORECASE)
            elif zone == 'subjectbody':
                target_text = subject + " " + body
                matched = re.search(re.escape(keyword), target_text, re.IGNORECASE)
            elif zone == 'from':
                target_text = from_email
                matched = target_text.lower().endswith(keyword.lower())
            else:
                continue

            if matched:
                imap.copy(num, folder)
                imap.store(num, '+FLAGS', '\\Deleted')
                mails_moved += 1
                moved = True
                break

        if moved:
            break

    if moved:
        continue

    if spam_filter.is_spam(msg):
        junk_folder = imap_config.get('junk_folder', 'Junk')
        imap.copy(num, junk_folder)
        imap.store(num, '+FLAGS', '\\Deleted')
        mails_moved += 1

imap.expunge()

# Refaire un passage après le tri permet de mémoriser immédiatement les mails
# que ce cycle vient d'envoyer dans Junk. Une correction faite dans Thunderbird
# avant le prochain cycle pourra ainsi être reconnue.
try:
    spam_filter.learn_user_corrections(imap, imap_config)
except Exception as exc:
    print(f"[SPAM FILTER] Mise à jour du suivi Junk impossible: {exc}")

imap.logout()

if mails_moved > 0:
    print(f"{mails_moved} mails déplacés.")
else:
    print("Rien à traiter.")
