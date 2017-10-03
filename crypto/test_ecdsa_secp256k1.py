from pytest import fixture
from pytest import raises

from common.crypto import ecdsa_secp256k1


class TestECDSASecp256k1:

    @fixture
    def tmpfile(self, tmpdir):
        return str(tmpdir.join("keyfile.pem"))

    def test_VerifyingACompletelyBrokenSignature_RaisesInvalidSignature(self):
        key, pubkey = ecdsa_secp256k1.generate_keys()

        with raises(ecdsa_secp256k1.InvalidSignature):
            ecdsa_secp256k1.verify(pubkey, "completelyBogûsÇigna_!ture", "not a chance!")

    def test_SigningSomeTextWithKey1AndVerifyingWithPubkey1_DoesNotRaiseInvalidSignature(self):
        plain_text = "some text"
        key, pubkey = ecdsa_secp256k1.generate_keys()

        valid_signature = ecdsa_secp256k1.sign(key, plain_text)
        ecdsa_secp256k1.verify(pubkey, valid_signature, plain_text)

    def test_SigningSomeTextWithKey1AndVerifyingWithPubkey1_RaisesInvalidSignature(self):
        plain_text = "some text"
        key_1, pubkey_1 = ecdsa_secp256k1.generate_keys()
        key_2, pubkey_2 = ecdsa_secp256k1.generate_keys()

        with raises(ecdsa_secp256k1.InvalidSignature):
            valid_signature = ecdsa_secp256k1.sign(key_1, plain_text)
            ecdsa_secp256k1.verify(pubkey_2, valid_signature, plain_text)

    def test_DumpingAPrivateKeyAndLoadingTheRespectiveReturnsTheSameKey(self, tmpfile):
        key, pubkey = ecdsa_secp256k1.generate_keys()

        ecdsa_secp256k1.dump_key(key, tmpfile)
        loaded_key, loaded_pubkey = ecdsa_secp256k1.load_keys(tmpfile)

        assert key == loaded_key
        assert pubkey == loaded_pubkey

    def test_EncryptingAndDecryptingAPrivateKeyWithPasswordReturnsTheSameKey(self, tmpfile):
        key, pubkey = ecdsa_secp256k1.generate_keys()

        cypher_text = ecdsa_secp256k1.encrypt_message(key, password="1234")
        recovered_key = ecdsa_secp256k1.decrypt_message(cypher_text, password="1234")

        assert key != cypher_text
        assert key == recovered_key

    def test_DumpingAPrivateKeyWithPasswordAndLoadingTheRespectiveReturnsTheSameKey(self, tmpfile):
        key, pubkey = ecdsa_secp256k1.generate_keys()

        ecdsa_secp256k1.dump_key(key, tmpfile, password="1234")
        loaded_key, loaded_pubkey = ecdsa_secp256k1.load_keys(tmpfile, password="1234")

        assert key == loaded_key
        assert pubkey == loaded_pubkey

    def test_DumpingAPublicKeyAndLoadingTheRespectiveReturnsTheSameKey(self,  tmpfile):
        key, pubkey = ecdsa_secp256k1.generate_keys()

        ecdsa_secp256k1.dump_pubkey(pubkey, tmpfile)
        loaded_pubkey = ecdsa_secp256k1.load_pubkey(tmpfile)

        assert pubkey == loaded_pubkey
