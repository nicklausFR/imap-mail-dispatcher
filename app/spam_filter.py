import os
import sys
import email
import imaplib
import joblib
import yaml
import json
import re
from pathlib import Path
from email.header import decode_header
from email.utils import parseaddr
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

APP_DIR = Path(__file__).resolve().parent
MODEL_PATH = str(APP_DIR / 'spam_model.pkl')
VECTORIZER_PATH = str(APP_DIR / 'vectorizer.pkl')
STATUS_PATH = str(APP_DIR / 'spam_status.json')
WHITELIST_PATH = str(APP_DIR / 'spam_whitelist.yaml')
JUNK_STATE_PATH = str(APP_DIR / 'spam_junk_state.json')


def load_config():
    with open(APP_DIR / 'imap.yaml', 'r') as f:
        return yaml.safe_load(f)


def decode_subject(subject):
    if not subject:
        return ""
    decoded_fragments = decode_header(subject)
    decoded_string = ""
    for fragment, encoding in decoded_fragments:
        if isinstance(fragment, bytes):
            try:
                decoded_string += fragment.decode(encoding or 'utf-8', errors='ignore')
            except Exception:
                decoded_string += fragment.decode(errors='ignore')
        else:
            decoded_string += fragment
    return decoded_string


def _sender_address(msg_or_sender):
    if hasattr(msg_or_sender, 'get'):
        value = msg_or_sender.get('From', '')
    else:
        value = msg_or_sender or ''
    return parseaddr(str(value))[1].strip().lower()


def _sender_domain(sender):
    sender = _sender_address(sender)
    if '@' not in sender:
        return ''
    return sender.rsplit('@', 1)[1]


def load_whitelist():
    if not os.path.exists(WHITELIST_PATH):
        return {'senders': [], 'domains': []}

    try:
        with open(WHITELIST_PATH, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"[SPAM FILTER] Impossible de lire la whitelist: {exc}")
        return {'senders': [], 'domains': []}

    senders = set()
    for sender in data.get('senders', []) or []:
        normalized = _sender_address(sender)
        if normalized:
            senders.add(normalized)

    domains = set()
    for domain in data.get('domains', []) or []:
        normalized = str(domain).strip().lower().lstrip('@')
        if normalized:
            domains.add(normalized)

    return {'senders': sorted(senders), 'domains': sorted(domains)}


def save_whitelist(whitelist):
    os.makedirs(os.path.dirname(WHITELIST_PATH), exist_ok=True)
    temp_path = WHITELIST_PATH + '.tmp'
    with open(temp_path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(
            {
                'senders': sorted(set(whitelist.get('senders', []))),
                'domains': sorted(set(whitelist.get('domains', []))),
            },
            f,
            allow_unicode=True,
            sort_keys=False,
        )
    os.replace(temp_path, WHITELIST_PATH)


def is_whitelisted(msg_or_sender):
    sender = _sender_address(msg_or_sender)
    if not sender:
        return False

    whitelist = load_whitelist()
    if sender in whitelist['senders']:
        return True

    domain = _sender_domain(sender)
    return bool(domain and domain in whitelist['domains'])


def add_sender_to_whitelist(sender):
    """Ajoute uniquement l'adresse exacte, jamais tout le domaine automatiquement."""
    sender = _sender_address(sender)
    if not sender:
        return False

    whitelist = load_whitelist()
    if sender in whitelist['senders']:
        return False

    whitelist['senders'].append(sender)
    save_whitelist(whitelist)
    print(f"[SPAM FILTER] Correction utilisateur: {sender} ajouté à la whitelist.")
    return True


def _normalize_message_id(value):
    if not value:
        return ''
    return ' '.join(str(value).split()).strip()


def _load_junk_state():
    if not os.path.exists(JUNK_STATE_PATH):
        return {'version': 1, 'initialized': False, 'uidvalidity': '', 'messages': {}}

    try:
        with open(JUNK_STATE_PATH, 'r', encoding='utf-8') as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[SPAM FILTER] Impossible de lire l'état Junk: {exc}")
        return {'version': 1, 'initialized': False, 'uidvalidity': '', 'messages': {}}

    messages = state.get('messages', {})
    if not isinstance(messages, dict):
        messages = {}

    return {
        'version': 1,
        'initialized': bool(state.get('initialized', False)),
        'uidvalidity': str(state.get('uidvalidity', '')),
        'messages': messages,
    }


def _save_junk_state(uidvalidity, messages):
    os.makedirs(os.path.dirname(JUNK_STATE_PATH), exist_ok=True)
    temp_path = JUNK_STATE_PATH + '.tmp'
    state = {
        'version': 1,
        'initialized': True,
        'uidvalidity': str(uidvalidity or ''),
        'messages': messages,
    }
    with open(temp_path, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(temp_path, JUNK_STATE_PATH)


def _selected_uidvalidity(imap):
    try:
        _, values = imap.response('UIDVALIDITY')
    except Exception:
        return ''
    if not values:
        return ''
    value = values[-1]
    if isinstance(value, bytes):
        value = value.decode('ascii', errors='ignore')
    return str(value or '').strip()


def _fetch_headers_by_uid(imap, uids):
    """Retourne {uid: {message_id, sender}} en ne lisant que deux en-têtes."""
    result = {}
    uid_list = [str(uid) for uid in uids if str(uid).isdigit()]

    # On découpe pour éviter une commande IMAP trop longue si Junk est volumineux.
    for offset in range(0, len(uid_list), 100):
        chunk = uid_list[offset:offset + 100]
        if not chunk:
            continue

        status, data = imap.uid(
            'fetch',
            ','.join(chunk),
            '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID FROM)])',
        )
        if status != 'OK':
            return None

        for item in data or []:
            if not isinstance(item, tuple) or len(item) < 2:
                continue

            meta = item[0]
            if isinstance(meta, str):
                meta = meta.encode('ascii', errors='ignore')
            match = re.search(rb'\bUID\s+(\d+)\b', meta or b'')
            if not match:
                continue

            uid = match.group(1).decode('ascii')
            msg = email.message_from_bytes(item[1])
            message_id = _normalize_message_id(msg.get('Message-ID', ''))
            sender = _sender_address(msg)
            result[uid] = {
                'message_id': message_id,
                'sender': sender,
            }

    return result


def _message_id_exists_in_folder(imap, folder, message_id):
    status, _ = imap.select(folder, readonly=True)
    if status != 'OK':
        return None

    # HEADER est bien moins coûteux que de télécharger le message. La valeur
    # est quotée pour les serveurs IMAP stricts.
    escaped = str(message_id).replace('\\', '\\\\').replace('"', '\\"')
    status, messages = imap.search(None, 'HEADER', 'Message-ID', f'"{escaped}"')
    if status != 'OK':
        return None
    return bool(messages and messages[0].split())


def _list_selectable_folders(imap):
    """Retourne les dossiers IMAP sélectionnables tels que le serveur les annonce."""
    status, rows = imap.list()
    if status != 'OK':
        return None

    folders = []
    for row in rows or []:
        if not row:
            continue
        if isinstance(row, str):
            raw = row.encode('utf-8', errors='ignore')
        else:
            raw = row

        # Format IMAP LIST courant : (flags) "separateur" "nom du dossier"
        match = re.match(rb'^\(([^)]*)\)\s+(?:"(?:[^"\\]|\\.)*"|NIL)\s+(.+)$', raw)
        if not match:
            continue

        flags = match.group(1).lower()
        if b'\\noselect' in flags:
            continue

        mailbox = match.group(2).strip()
        if len(mailbox) >= 2 and mailbox[:1] == b'"' and mailbox[-1:] == b'"':
            mailbox = mailbox[1:-1]
            mailbox = mailbox.replace(b'\\"', b'"').replace(b'\\\\', b'\\')

        if mailbox:
            folders.append(mailbox)

    return folders


def _folder_display_name(folder):
    if isinstance(folder, bytes):
        return folder.decode('utf-8', errors='replace')
    return str(folder)


def _is_unsafe_correction_folder(folder, junk_folder):
    """Évite de considérer Junk/Corbeille comme une validation utilisateur."""
    name = _folder_display_name(folder).strip().strip('"').lower()
    junk = str(junk_folder).strip().strip('"').lower()

    if name == junk:
        return True

    unsafe_names = {
        'junk', 'spam', 'trash', 'deleted', 'deleted messages',
        'corbeille', 'indesirables', 'indésirables',
    }
    leaf = re.split(r'[/\\.]', name)[-1]
    return leaf in unsafe_names


def _message_id_exists_in_normal_folder(imap, imap_config, message_id):
    """
    Cherche le Message-ID dans tous les dossiers IMAP sélectionnables sauf
    Junk/Spam/Corbeille. Le scan n'est effectué que lorsqu'un message vient de
    disparaître de Junk, donc il n'alourdit pas le cycle normal.

    Retourne (trouve, dossier). trouve=None signifie que la vérification IMAP
    n'a pas pu être menée correctement.
    """
    junk_folder = imap_config.get('junk_folder', 'Junk')
    folders = _list_selectable_folders(imap)
    if folders is None:
        return None, None

    # INBOX en premier, puis les autres dossiers. Cela couvre aussi les dossiers
    # de tri comme "Connections", "Factures", etc.
    inbox = imap_config.get('imap_folder_inbox', 'INBOX')
    ordered = []
    inbox_lower = str(inbox).lower()
    for folder in folders:
        if _folder_display_name(folder).lower() == inbox_lower:
            ordered.insert(0, folder)
        else:
            ordered.append(folder)

    checked = 0
    for folder in ordered:
        if _is_unsafe_correction_folder(folder, junk_folder):
            continue

        found = _message_id_exists_in_folder(imap, folder, message_id)
        if found is None:
            # Un dossier non sélectionnable malgré LIST ne doit pas annuler les
            # recherches déjà possibles dans les autres dossiers.
            continue
        checked += 1
        if found:
            return True, _folder_display_name(folder)

    if checked == 0:
        return None, None
    return False, None



def rescue_whitelisted_from_junk(imap, imap_config):
    """
    Fait respecter la whitelist même si un autre antispam/client a placé le
    message directement dans Junk avant que imap-mail-dispatcher ne voie INBOX.

    Les messages dont l'expéditeur exact (ou le domaine explicitement présent
    dans la whitelist) est autorisé sont remis dans INBOX. Le traitement normal
    de imap-mail-dispatcher pourra ensuite appliquer les règles de tri (Connections,
    Factures, etc.) s'ils sont encore non lus.
    """
    whitelist = load_whitelist()
    if not whitelist['senders'] and not whitelist['domains']:
        return 0

    junk_folder = imap_config.get('junk_folder', 'Junk')
    inbox_folder = imap_config.get('imap_folder_inbox', 'INBOX')

    status, _ = imap.select(junk_folder, readonly=False)
    if status != 'OK':
        print(f"[SPAM FILTER] Impossible d'ouvrir {junk_folder} pour appliquer la whitelist.")
        return 0

    status, data = imap.search(None, 'ALL')
    if status != 'OK' or not data or not data[0]:
        return 0

    moved = 0
    for num in data[0].split():
        status, rows = imap.fetch(num, '(BODY.PEEK[HEADER.FIELDS (FROM MESSAGE-ID SUBJECT)])')
        if status != 'OK' or not rows:
            continue

        raw_headers = None
        for row in rows:
            if isinstance(row, tuple) and len(row) >= 2:
                raw_headers = row[1]
                break
        if not raw_headers:
            continue

        msg = email.message_from_bytes(raw_headers)
        sender = _sender_address(msg)
        if not sender or not is_whitelisted(sender):
            continue

        status, _ = imap.copy(num, inbox_folder)
        if status != 'OK':
            print(f"[SPAM FILTER] Whitelist détectée pour {sender}, mais copie vers {inbox_folder} impossible.")
            continue

        imap.store(num, '+FLAGS', '\\Deleted')
        moved += 1
        print(f"[SPAM FILTER] Whitelist appliquée dans {junk_folder}: {sender} -> {inbox_folder}.")

    if moved:
        imap.expunge()
    return moved


def learn_user_corrections(imap, imap_config):
    """
    Apprend une correction explicite de l'utilisateur sans supprimer le filtre
    existant.

    Un message présent dans Junk à un cycle puis absent au cycle suivant est
    considéré comme un faux positif si son Message-ID est retrouvé dans un
    dossier normal (INBOX, Connections, Factures, etc.). Son expéditeur exact
    est alors ajouté à la whitelist. Junk/Spam/Corbeille sont exclus.
    """
    junk_folder = imap_config.get('junk_folder', 'Junk')
    status, _ = imap.select(junk_folder, readonly=True)
    if status != 'OK':
        print(f"[SPAM FILTER] Impossible d'ouvrir {junk_folder} pour le suivi des corrections.")
        return 0

    uidvalidity = _selected_uidvalidity(imap)
    status, data = imap.uid('search', None, 'ALL')
    if status != 'OK':
        print(f"[SPAM FILTER] Impossible de lire les UID de {junk_folder}.")
        return 0

    current_uids = {
        uid.decode('ascii') if isinstance(uid, bytes) else str(uid)
        for uid in ((data[0].split() if data and data[0] else []))
    }

    previous = _load_junk_state()

    # Au premier passage, ou si le serveur a changé UIDVALIDITY, on établit une
    # base de référence sans interpréter l'historique comme une correction.
    if (not previous['initialized']) or (
        previous['uidvalidity'] and uidvalidity and previous['uidvalidity'] != uidvalidity
    ):
        headers = _fetch_headers_by_uid(imap, sorted(current_uids, key=int))
        if headers is None:
            return 0
        _save_junk_state(uidvalidity, headers)
        print(f"[SPAM FILTER] Suivi Junk initialisé avec {len(headers)} message(s).")
        return 0

    previous_messages = previous['messages']
    previous_uids = set(previous_messages)
    removed_uids = previous_uids - current_uids
    new_uids = current_uids - previous_uids

    whitelisted = 0
    for uid in sorted(removed_uids, key=int):
        old = previous_messages.get(uid) or {}
        message_id = _normalize_message_id(old.get('message_id', ''))
        sender = old.get('sender', '')
        if not message_id or not sender:
            continue

        found_elsewhere, destination = _message_id_exists_in_normal_folder(
            imap, imap_config, message_id
        )
        if found_elsewhere is None:
            # Ne pas perdre l'événement si le serveur IMAP a eu un problème :
            # l'état reste inchangé et la vérification sera retentée au cycle suivant.
            print("[SPAM FILTER] Vérification des dossiers impossible; correction reportée.")
            return whitelisted
        if found_elsewhere:
            if add_sender_to_whitelist(sender):
                print(f"[SPAM FILTER] Mail sorti de Junk vers {destination}: validation utilisateur.")
                whitelisted += 1

    # Conserver les métadonnées des messages toujours présents et ne lire les
    # en-têtes que pour les nouveaux UID. Le coût normal reste donc très faible.
    next_messages = {
        uid: previous_messages[uid]
        for uid in current_uids & previous_uids
        if uid in previous_messages
    }
    if new_uids:
        # La recherche d'une correction a sélectionné un autre dossier. Revenir
        # dans Junk avant le FETCH par UID des nouveaux messages.
        status, _ = imap.select(junk_folder, readonly=True)
        if status != 'OK':
            return whitelisted
        new_headers = _fetch_headers_by_uid(imap, sorted(new_uids, key=int))
        if new_headers is None:
            return whitelisted
        next_messages.update(new_headers)

    _save_junk_state(uidvalidity or previous['uidvalidity'], next_messages)
    return whitelisted


def connect_imap(imap_config):
    imap = imaplib.IMAP4_SSL(imap_config['imap_server'], imap_config['imap_port'])
    credential_dir = os.environ.get('CREDENTIALS_DIRECTORY')
    if not credential_dir:
        raise RuntimeError('CREDENTIALS_DIRECTORY is not set')
    credential_file = Path(credential_dir) / 'imap_password'
    imap_password = credential_file.read_text(encoding='utf-8')
    imap.login(imap_config['imap_user'], imap_password)
    del imap_password
    return imap


def count_junk_mails(imap_config):
    imap = connect_imap(imap_config)
    folder = imap_config.get('junk_folder', 'Junk')
    imap.select(folder)
    status, messages = imap.search(None, 'ALL')
    imap.logout()
    if status != 'OK':
        return 0
    return len(messages[0].split())


def fetch_mail_texts(imap_config, folder, limit=None):
    imap = connect_imap(imap_config)
    imap.select(folder)

    status, messages = imap.search(None, 'ALL')
    if status != 'OK':
        print(f"[SPAM FILTER] Erreur lors de la récupération des mails du dossier {folder}")
        imap.logout()
        return []

    mail_ids = messages[0].split()
    if limit:
        mail_ids = mail_ids[-limit:]

    texts = []
    for num in mail_ids:
        status, data = imap.fetch(num, '(BODY.PEEK[])')
        if status != 'OK':
            continue
        msg = email.message_from_bytes(data[0][1])
        subject = decode_subject(msg.get('Subject', ''))
        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode(errors='ignore')
                    except Exception:
                        continue
        else:
            try:
                body += msg.get_payload(decode=True).decode(errors='ignore')
            except Exception:
                continue

        texts.append((subject + " " + body).lower())

    imap.logout()
    return texts


def load_status():
    if os.path.exists(STATUS_PATH):
        with open(STATUS_PATH, 'r') as f:
            return json.load(f)
    return {}


def save_status(new_status):
    with open(STATUS_PATH, 'w') as f:
        json.dump(new_status, f)


def needs_training(imap_config):
    current_count = count_junk_mails(imap_config)
    previous_status = load_status()
    previous_count = previous_status.get('Junk', -1)

    if current_count != previous_count:
        print(f"[SPAM FILTER] Changement détecté dans Junk : avant={previous_count}, maintenant={current_count}")
        save_status({'Junk': current_count})
        return True
    else:
        print("[SPAM FILTER] Aucun changement détecté dans Junk.")
        return False


def train_model():
    imap_config = load_config()

    if not needs_training(imap_config):
        print("[SPAM FILTER] Pas d'apprentissage nécessaire.")
        return

    print("[SPAM FILTER] Démarrage de l'apprentissage...")

    spam_folder = imap_config.get('junk_folder', 'Junk')
    inbox_folder = imap_config.get('imap_folder_inbox', 'INBOX')
    spam_texts = fetch_mail_texts(imap_config, spam_folder)
    ham_texts = fetch_mail_texts(imap_config, inbox_folder, limit=50)

    if not spam_texts or not ham_texts:
        print("[SPAM FILTER] Pas assez de données pour entraîner le modèle.")
        return

    texts = spam_texts + ham_texts
    labels = [1] * len(spam_texts) + [0] * len(ham_texts)

    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(texts)

    model = MultinomialNB()
    model.fit(X, labels)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)

    print(f"[SPAM FILTER] Modèle entraîné avec {len(spam_texts)} spams et {len(ham_texts)} hams.")


def is_spam(msg):
    # La décision explicite de l'utilisateur est prioritaire sur tout le reste,
    # y compris un éventuel X-Spam-Flag: YES et le modèle bayésien existant.
    if is_whitelisted(msg):
        sender = _sender_address(msg)
        print(f"[SPAM FILTER] Whitelist: {sender} accepté.")
        return False

    if 'x-spam-flag' in msg and msg['x-spam-flag'].lower() == 'yes':
        return True

    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        return False

    subject = decode_subject(msg.get('Subject', ''))
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode(errors='ignore')
                except Exception:
                    continue
    else:
        try:
            body += msg.get_payload(decode=True).decode(errors='ignore')
        except Exception:
            pass

    text = (subject + " " + body).lower()

    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)

    X = vectorizer.transform([text])
    prediction = model.predict(X)
    return prediction[0] == 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        train_model()
