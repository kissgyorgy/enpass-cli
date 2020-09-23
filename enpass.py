#!/usr/bin/env python3
import os
import binascii
import hashlib
from pathlib import Path
from pysqlcipher3 import dbapi2 as sqlite
from Crypto.Cipher import AES

# Sources:
#   - https://www.enpass.io/docs/security-whitepaper-enpass/vault.html
#   - https://discussion.enpass.io/index.php?/topic/4446-enpass-6-encryption-details/
#   - https://www.zetetic.net/sqlcipher/sqlcipher-api/
PBKDF2_ROUNDS = 100_000
ENPASS_DB = os.environ["ENPASS_DB"]
KEY_FILE = os.environ["ENPASS_KEY_FILE"]
PASSWORD = os.environb[b"ENPASS_PASSWORD"]


def make_master_password(password: bytes, key_path: Path):
    key_hex_xml = Path(key_path).read_bytes()
    # no need to use XML lib for such a simple string operation
    cut_key_value = slice(5, -6)
    key_hex = key_hex_xml[cut_key_value]
    key_bytes = binascii.unhexlify(key_hex)
    return password + key_bytes


def main():
    master_password = make_master_password(PASSWORD, KEY_FILE)

    # The first 16 bytes of the database file are used as salt
    enpass_db_salt = open(ENPASS_DB, "rb").read(16)

    # The database key is derived from the master password
    # and the database salt with 100k iterations of PBKDF2-HMAC-SHA512
    enpass_db_key = hashlib.pbkdf2_hmac(
        "sha512", master_password, enpass_db_salt, PBKDF2_ROUNDS
    )

    # The raw key for the sqlcipher database is given
    # by the first 64 characters of the hex-encoded key
    enpass_db_hex_key = enpass_db_key.hex()[:64]

    conn = sqlite.connect(ENPASS_DB)

    c = conn.cursor()
    c.row_factory = sqlite.Row
    c.execute(f"PRAGMA key=\"x'{enpass_db_hex_key}'\";")
    c.execute("PRAGMA cipher_compatibility = 3;")
    c.execute("SELECT * FROM Identity;")

    identity = c.fetchone()
    print(identity["Info"].hex())
