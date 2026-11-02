"""Шифрование обратной связи на компьютере пользователя (баг 025).

Сообщение (тема, текст, контакт, среда, журнал, картинки) упаковывается в JSON, сжимается и
шифруется **открытым** ключом разработчиков: X25519 (одноразовая пара на сообщение) → HKDF-SHA256 →
AES-256-GCM. Расшифровать может только владелец закрытого ключа (его нет ни в программе, ни в
репозиториях открытым; дешифратор — tools/feedback_decrypt.py). Подмена шифротекста — ошибка GCM.

В issue уходит только «Ошибка · <id>», версия и канал, и шифротекст base64 частями (тело issue и,
если не влезло, комментарии — до 65536 символов каждое): файлов в репозитории обратной связи
больше нет, токену нужно только право Issues.

Здесь же — запутывание вшитого токена (encode_token/decode_token): AES-GCM ключом из констант
программы. Это не секретность (ключ в той же программе), а защита от сканеров и простого
извлечения; настоящая защита — права токена и скрытие незашифрованного в репозитории.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import zlib

# открытый ключ разработчиков (X25519, base64); пара — tools/feedback_keys.py new
PUBLIC_KEY = "b3lzfBHut7Sh7uYw3W59Opggo+6+O1iaeQgZD6AJ3Uo="

MAGIC = b"KLH1"
INFO = b"KLH-feedback v1"
TAG = "klh-sealed v1"
PART_CHARS = 60000                 # base64 на одну часть (тело issue — до 65536 символов)
MAX_PARTS = 25                     # ~1,1 МБ шифротекста — больше не отправляем
_PART_RE = re.compile(r"```text\n([A-Za-z0-9+/=\n]+?)\n```")

_TOKEN_PEPPER = b"KLH\x1f feedback\x07token\x1e2026"


class SealError(ValueError):
    """Нечем или нечего шифровать / не расшифровывается."""


def _hkdf(secret: bytes, salt: bytes, info: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(secret)


def seal(data: bytes, public_b64: str | None = None) -> bytes:
    """data → MAGIC | одноразовый открытый ключ (32) | nonce (12) | AES-GCM(data)."""
    pub_b64 = PUBLIC_KEY if public_b64 is None else public_b64
    if not pub_b64:
        raise SealError("в этой сборке нет ключа шифрования обратной связи")
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError as e:
        raise SealError("нет модуля cryptography — сообщение не зашифровать") from e
    pub_raw = base64.b64decode(pub_b64)
    eph = X25519PrivateKey.generate()
    eph_raw = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = _hkdf(eph.exchange(X25519PublicKey.from_public_bytes(pub_raw)),
                eph_raw + pub_raw, INFO)
    nonce = os.urandom(12)
    return MAGIC + eph_raw + nonce + AESGCM(key).encrypt(nonce, data, MAGIC)


def unseal(blob: bytes, private_raw: bytes) -> bytes:
    """Обратное seal — только у разработчиков (закрытый ключ). Чужое/подменённое — SealError."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    if len(blob) < 4 + 32 + 12 + 16 or blob[:4] != MAGIC:
        raise SealError("не шифротекст KLH")
    priv = X25519PrivateKey.from_private_bytes(private_raw)
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    eph_raw, nonce, ct = blob[4:36], blob[36:48], blob[48:]
    key = _hkdf(priv.exchange(X25519PublicKey.from_public_bytes(eph_raw)), eph_raw + pub_raw, INFO)
    try:
        return AESGCM(key).decrypt(nonce, ct, MAGIC)
    except InvalidTag as e:
        raise SealError("не расшифровывается: чужой ключ или шифротекст изменён") from e


def pack(fields: dict, images: list[bytes]) -> bytes:
    """Сообщение и картинки (байты JPEG/PNG) → сжатый JSON для seal."""
    data = dict(fields, v=1, images=[base64.b64encode(b).decode("ascii") for b in images])
    return zlib.compress(json.dumps(data, ensure_ascii=False).encode("utf-8"), 9)


def unpack(data: bytes, max_bytes: int = 20_000_000) -> tuple[dict, list[bytes]]:
    """Обратное pack, с пределом размера после распаковки (не «zip-бомба»)."""
    d = zlib.decompressobj()
    raw = d.decompress(data, max_bytes)
    if d.unconsumed_tail:
        raise SealError("сообщение слишком большое после распаковки")
    fields = json.loads(raw.decode("utf-8"))
    if not isinstance(fields, dict):
        raise SealError("не сообщение KLH")
    images = [base64.b64decode(s) for s in fields.pop("images", []) if isinstance(s, str)]
    return fields, images


def to_parts(blob: bytes) -> list[str]:
    """Шифротекст → части base64 для тела issue и комментариев."""
    text = base64.b64encode(blob).decode("ascii")
    parts = [text[i:i + PART_CHARS] for i in range(0, len(text), PART_CHARS)] or [""]
    if len(parts) > MAX_PARTS:
        raise SealError("сообщение с картинками слишком большое — уберите картинку")
    return parts


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def part_text(n: int, total: int, msg_id: str, chunk: str, header: str = "") -> str:
    """Текст тела issue (n = 1, с заголовком) или комментария (n > 1)."""
    marker = f"<!-- {TAG} id={msg_id} part={n}/{total} -->"
    block = "```text\n" + "\n".join(chunk[i:i + 76] for i in range(0, len(chunk), 76)) + "\n```"
    return "\n".join(x for x in (marker, header, block) if x) + "\n"


def parts_from_texts(texts: list[str], msg_id: str) -> bytes:
    """Тексты тела и комментариев issue → шифротекст (части по номерам; чего-то нет — ошибка)."""
    found: dict[int, str] = {}
    total = 0
    head = re.compile(rf"<!-- {re.escape(TAG)} id={re.escape(msg_id)} part=(\d+)/(\d+) -->")
    for t in texts:
        m = head.search(t or "")
        b = _PART_RE.search(t or "")
        if not m or not b:
            continue
        n, total = int(m.group(1)), int(m.group(2))
        found.setdefault(n, b.group(1).replace("\n", ""))
    if not total or sorted(found) != list(range(1, total + 1)):
        raise SealError(f"части шифротекста неполные: {sorted(found)} из {total}")
    return base64.b64decode("".join(found[i] for i in range(1, total + 1)), validate=True)


# ------------------------------------------------------------- вшитый токен (запутывание)
def _token_key(salt: bytes) -> bytes:
    return _hkdf(_TOKEN_PEPPER + bytes(reversed(INFO)), salt, b"KLH-feedback token")


def encode_token(token: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_token_key(salt)).encrypt(nonce, token.strip().encode("utf-8"), None)
    return "2:" + base64.b64encode(salt + nonce + ct).decode("ascii")


def decode_token(value: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.b64decode(value.split(":", 1)[1])
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    return AESGCM(_token_key(salt)).decrypt(nonce, ct, None).decode("utf-8").strip()
