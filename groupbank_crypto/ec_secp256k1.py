import bitcoin

import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

SERIALIZED_KEY_LENGTH = 52
SIGNATURE_LENGTH = 88

PRIVKEY_FORMAT = 'wif_compressed'
PUBKEY_FORMAT = 'hex_compressed'


class InvalidSignature(Exception):
    """ Raised when a verification of a signature fails. """


class InvalidKey(Exception):
    """ Raised when a key isn't valid. """


class InvalidPassword(Exception):
    """ Raised when a key isn't valid. """


def generate_keys() -> (str, str):
    """
    Generates a pair of private and public keys

    :return: 2-tuple with the private and public key in string format.
    """
    raw_private_key = bitcoin.random_key()
    raw_public_key = bitcoin.privkey_to_pubkey(raw_private_key)
    private_key = bitcoin.encode_privkey(raw_private_key, PRIVKEY_FORMAT)
    public_key = bitcoin.encode_pubkey(raw_public_key, PUBKEY_FORMAT)
    return private_key, public_key


def sign(key: str, payload: str) -> str:
    """
    Signs a message with the given key.

    :param key:     private key used to make the signature.
    :param payload:  message to sign.
    :return: signature
    """
    return bitcoin.ecdsa_sign(payload, key)


def verify(pubkey: str, signature: str, payload: str):
    """
    Verifies if a signature is valid. Expects the list of values included in
    the signature to be in the same order as they were signed. If the
    verification fails it raises an InvalidSignature exception.

    :param pubkey:      public key used to verify the signature.
    :param signature:   signature to verify encoded in base 64.
    :param payload:      values included in the signature.
    :return:
    :raise InvalidSignature: if the signature is invalid.
    """
    try:
        if not bitcoin.ecdsa_verify(payload, signature, pubkey):
            raise InvalidSignature()
    except Exception:
        raise InvalidSignature()


def ecdh_key_agreement(self_private_key: str, other_public_key: str) -> bytes:
    """
    Creates a shared symmetric key between two entities using elyptic curve diffie-hellman

    :param self_private_key: the private key of the entity using the method
    :param other_public_key: the public key to compute the shared symmetric key with
    :return: a bytes symmetric key derived from the computed shared secret
    """
    # ECDH is simply an EC multiplication of a private key with a public key
    shared_secret = bitcoin.multiply(other_public_key, self_private_key)

    # the shared key is the x coordinate of the computed EC point
    shared_key = bitcoin.decode_pubkey(shared_secret)[0]

    # a bytes key is derived from the shared secret
    return hashlib.sha256(hex(shared_key).encode()).digest()


def _symmetric_key_from_password(password: str) -> bytes:

    """
    Derives a symmetric key suitable for AES-CFB from a given string password.
    A slow key derivation function is used to slow down brute force attacks on
    cypher texts encrypted with this password.

    :param password: a string to be used as a password
    :return: a bytes symmetric key suitable for AES-CFB
    """
    return hashlib.pbkdf2_hmac(password=password.encode(),
                               salt=b'These derived keys must not be stored on a server',
                               hash_name='sha256',
                               iterations=200000)


def _raw_encrypt_message(plaintext: str, symmetric_key: bytes) -> str:
    """
    Private method to encrypt a message string with a bytes symmetric key

    :param plaintext: the plaintext string
    :param symmetric_key: a bytes symmetric key suitable for AES-CFB encryption
    :return: the encrypted, serialized, cypher text
    """
    iv = get_random_bytes(16)
    aes_cipher = AES.new(symmetric_key, AES.MODE_CFB, iv)

    plaintext_bytes = plaintext.encode()
    cypher_text = aes_cipher.encrypt(plaintext_bytes)
    # include the IV in the serialized
    serialized_cypher_text = b64encode(iv + cypher_text).decode()
    return serialized_cypher_text


def _raw_decrypt_message(serialized_cypher_text: str, symmetric_key: bytes) -> str:
    """
    Private method to decrypt a message string with a bytes symmetric key

    :param serialized_cypher_text: the encrypted serialized text
    :param symmetric_key: a bytes symmetric key suitable for AES-CFB encryption
    :return: the decrypted plaintext string
    """
    # iv is included at the start
    iv = b64decode(serialized_cypher_text)[0:16]
    cypher_text = b64decode(serialized_cypher_text)[16:]

    aes_cipher = AES.new(symmetric_key, AES.MODE_CFB, iv)
    try:
        plaintext_bytes = aes_cipher.decrypt(cypher_text)
        plaintext = plaintext_bytes.decode()
        return plaintext
    except UnicodeDecodeError:
        raise InvalidPassword


def encrypt_with_password(plaintext: str, password: str) -> str:
    """
    Encrypts the private key with a password and returns a base64 string of cypher text.

    :param plaintext: message plaintext.
    :param password: password to encrypt the key.
    :return: base64 string of the cypher text
    """
    return _raw_encrypt_message(plaintext, _symmetric_key_from_password(password))


def decrypt_with_password(serialized_cypher_text: str, password: str) -> str:
    """
    Decrypts the message with a password and returns it.

    :param serialized_cypher_text: the cypher text in a base64 string.
    :param password: password to decrypt the key.
    :return: message string
    """
    return _raw_decrypt_message(serialized_cypher_text, _symmetric_key_from_password(password))


def dump_key(private_key: str, key_file_path, password=None):
    """
    Dumps a private key to a key file in the wif_compressed format.
    Takes the password to encrypt the key file as an optional argument.

    :param private_key:          private key to dump to file.
    :param key_file_path: path to the key file in wif_compressed format.
    :param password:     password to encrypt the key file.
    """
    try:
        encoded_private_key = bitcoin.encode_privkey(private_key, PRIVKEY_FORMAT)
    except Exception as e:
        raise InvalidKey from e

    with open(key_file_path, "w") as key_file:
        if password:
            key_file.write(encrypt_with_password(encoded_private_key, password))
        else:
            key_file.write(encoded_private_key)


def load_keys(key_file_path, password=None) -> (str, str):
    """
    Loads the private and public keys from a key file in the PEM format.
    Takes the password to decrypt the key file as an optional argument.

    :param key_file_path: path to the key file in PEM format.
    :param password:     password to decrypt the key file.
    :return: 2-tuple with the private and public key in string format.
    """
    with open(key_file_path, "r") as key_file:
        try:
            if password:
                raw_private_key = bitcoin.decode_privkey(decrypt_with_password(key_file.read(), password))
            else:
                raw_private_key = bitcoin.decode_privkey(key_file.read())

            raw_public_key = bitcoin.privkey_to_pubkey(raw_private_key)
            private_key = bitcoin.encode_privkey(raw_private_key, PRIVKEY_FORMAT)
            public_key = bitcoin.encode_pubkey(raw_public_key, PUBKEY_FORMAT)
            return private_key, public_key
        except Exception as e:
            raise InvalidKey from e


def load_pubkey(key_file_path) -> str:
    """
    Loads a public key from a key file.
    Takes the password to decrypt the key file as an optional argument.

    :param key_file_path: path to the key file.
    :return: public key in string format.
    """
    try:
        with open(key_file_path, "r") as key_file:
            raw_public_key = bitcoin.decode_pubkey(key_file.read())
            return bitcoin.encode_pubkey(raw_public_key, PUBKEY_FORMAT)
    except Exception as e:
        raise InvalidKey from e


def dump_pubkey(pubkey: str, key_filepath):
    """
    Dumps a public key to a key file in the hex_compressed format.

    :param pubkey:       public key to dump to file.
    :param key_filepath: path to the key file in hex_compressed format.
    """
    try:
        with open(key_filepath, "w") as key_file:
            key_file.write(bitcoin.encode_pubkey(pubkey, PUBKEY_FORMAT))
    except Exception as e:
        raise InvalidKey from e
