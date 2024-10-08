from matrix_content_scanner.utils.types import JsonDict

class CryptoHandler:
    def __init__(self, pickle_key: str, pickle_path: str) -> None: ...
    @property
    def public_key(self) -> str: ...
    def decrypt_body(self, ciphertext: str, mac: str, ephemeral: str) -> str: ...
    def encrypt(self, public_key: str, payload: str) -> PkMessage: ...

class PkMessage:
    @property
    def ephemeral_key(self) -> str: ...
    @property
    def mac(self) -> str: ...
    @property
    def ciphertext(self) -> str: ...

def decrypt_attachment(body: bytes, key_info: JsonDict) -> bytes: ...
