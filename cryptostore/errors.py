class CryptoStoreError(Exception):
    pass


# Algo no verificó (bloque, manifiesto, envolvente o firma): se detiene todo, sin resultados parciales
class VerificationError(CryptoStoreError):
    pass


class FormatError(CryptoStoreError):
    pass


class IdentityError(CryptoStoreError):
    pass
