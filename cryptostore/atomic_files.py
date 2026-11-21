import os
import tempfile


def write_file_atomically(path: str, content: bytes, permissions: int = 0o600) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    # Temporal en la misma carpeta, para que el renombrado final sea atómico
    file_descriptor, temporary_path = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(file_descriptor, "wb") as temporary_file:
            temporary_file.write(content)
            temporary_file.flush()
            # Forzar a disco antes de renombrar, por si se corta la luz
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_path, permissions)
        # Quien lea `path` ve el archivo viejo completo o el nuevo completo, nunca una mezcla
        os.replace(temporary_path, path)
    except BaseException:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)
        raise
