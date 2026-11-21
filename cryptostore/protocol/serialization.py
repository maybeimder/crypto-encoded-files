import base64
import binascii
import json

from cryptostore.errors import FormatError

_ALLOWED_JSON_SCALARS = (str, int, bool, type(None))


def canonical_json(value) -> bytes:
    _reject_unsupported_values(value)
    # Claves ordenadas y sin espacios: el mismo objeto siempre produce los mismos bytes,
    # requisito para firmarlo o calcular su huella
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _reject_unsupported_values(value) -> None:
    # Sin decimales: su forma escrita no es única (1.0, 1.00, 1e0)
    if isinstance(value, float):
        raise FormatError("el JSON canónico no admite números decimales")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise FormatError("las claves de un objeto JSON deben ser texto")
            _reject_unsupported_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_unsupported_values(item)
    elif not isinstance(value, _ALLOWED_JSON_SCALARS):
        raise FormatError(f"tipo no admitido en JSON canónico: {type(value).__name__}")


def to_base64(raw_bytes: bytes) -> str:
    return base64.b64encode(raw_bytes).decode("ascii")


def from_base64(text: str, expected_length: int | None = None) -> bytes:
    try:
        raw_bytes = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, AttributeError, UnicodeEncodeError) as error:
        raise FormatError("base64 inválido") from error
    if expected_length is not None and len(raw_bytes) != expected_length:
        raise FormatError(f"se esperaban {expected_length} bytes y llegaron {len(raw_bytes)}")
    return raw_bytes


def from_hex(text: str, expected_length: int) -> bytes:
    try:
        raw_bytes = bytes.fromhex(text)
    except (ValueError, TypeError) as error:
        raise FormatError("hexadecimal inválido") from error
    if len(raw_bytes) != expected_length:
        raise FormatError(f"se esperaban {expected_length} bytes y llegaron {len(raw_bytes)}")
    return raw_bytes


def require_field(data: dict, field_name: str, expected_type: type):
    if not isinstance(data, dict) or field_name not in data:
        raise FormatError(f"falta el campo '{field_name}'")
    value = data[field_name]
    # En Python bool es subclase de int; aquí no se aceptan como intercambiables
    if not isinstance(value, expected_type) or (expected_type is int and isinstance(value, bool)):
        raise FormatError(f"el campo '{field_name}' debe ser {expected_type.__name__}")
    return value
