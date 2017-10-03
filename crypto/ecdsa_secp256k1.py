import bitcoin
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

SERIALIZED_KEY_LENGTH = 52
SIGNATURE_LENGTH = 88

PRIVKEY_FORMAT = 'wif_compressed'
PUBKEY_FORMAT = 'hex_compressed'

SALT = get_random_bytes(16)
IV = get_random_bytes(16)  # todo: verify the properties the IV needs to have
# todo: IV needs to be included with the cypher text so that it can be decrypted


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


def get_cipher_from_password(password: str):
    derived_password = hashlib.pbkdf2_hmac(password=password.encode(),
                                           salt=SALT,
                                           hash_name='sha256',
                                           iterations=100000)

    return AES.new(derived_password, AES.MODE_CFB, IV)


def encrypt_message(plaintext: str, password: str) -> str:
    """
    Encrypts the private key with a password and returns a base64 string of cypher text.

    :param plaintext: message plaintext.
    :param password: password to encrypt the key.
    :return: base64 string of the cypher text
    """
    aes_cipher = get_cipher_from_password(password)

    plaintext_bytes = plaintext.encode()
    cypher_text = aes_cipher.encrypt(plaintext_bytes)
    serialized_cypher_text = b64encode(cypher_text).decode()
    return serialized_cypher_text


def decrypt_message(serialized_cypher_text: str, password: str) -> str:
    """
    Decrypts the message with a password and returns it.

    :param serialized_cypher_text: the cypher text in a base64 string.
    :param password: password to decrypt the key.
    :return: message string
    """
    aes_cipher = get_cipher_from_password(password)

    cypher_text = b64decode(serialized_cypher_text)
    try:
        plaintext_bytes = aes_cipher.decrypt(cypher_text)
        plaintext = plaintext_bytes.decode()
        return plaintext
    except UnicodeDecodeError:
        raise InvalidPassword


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
            key_file.write(encrypt_message(encoded_private_key, password))
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
                raw_private_key = bitcoin.decode_privkey(decrypt_message(key_file.read(), password))
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
    except ValueError:
        raise InvalidSignature()
