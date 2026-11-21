import platform
import time

MEBIBYTE = 1 << 20
KIBIBYTE = 1 << 10


def human_size(size_in_bytes: int) -> str:
    if size_in_bytes >= MEBIBYTE:
        return f"{size_in_bytes / MEBIBYTE:g} MiB"
    if size_in_bytes >= KIBIBYTE:
        return f"{size_in_bytes / KIBIBYTE:g} KiB"
    return f"{size_in_bytes} B"


def seconds(value: float) -> str:
    # Milisegundos para lo rápido, segundos para lo lento
    return f"{value * 1000:.2f} ms" if value < 1 else f"{value:.2f} s"


def speed(value: float | None) -> str:
    return "—" if value is None else f"{value:.0f} MiB/s"


def table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---:" for _ in headers) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def build_markdown(results: dict, repetitions: int) -> str:
    sections = [
        "# Mediciones",
        "",
        f"Generado por `cryptostore-bench` el {time.strftime('%Y-%m-%d %H:%M')}. "
        f"Promedio de {repetitions} repeticiones. Python {platform.python_version()}, "
        f"{platform.system()} {platform.machine()}, procesador: {platform.processor() or 'no informado'}.",
        "",
        "## Tiempo de cifrado y descifrado",
        "Bloques de 1 MiB, en memoria (sin red). El descifrado incluye verificar la firma, "
        "las huellas de cada bloque y la etiqueta AEAD antes de entregar el archivo.",
        "",
        table(["Tamaño", "Bloques", "Cifrado", "Velocidad", "Verificación + descifrado", "Velocidad"],
              [[human_size(row["file_size_bytes"]), str(row["blocks"]), seconds(row["encrypt_seconds"]),
                speed(row["encrypt_mib_per_second"]), seconds(row["decrypt_seconds"]),
                speed(row["decrypt_mib_per_second"])] for row in results["crypto_throughput"]]),
        "",
        "## Sobrecosto por bloque",
        f"Archivo de {human_size(results['block_size_overhead_file_size'])}. Sobrecosto = etiqueta de 16 B por bloque "
        "+ manifiesto (que lleva la huella de cada bloque). El nonce y los datos asociados no se almacenan.",
        "",
        table(["Tamaño de bloque", "Bloques", "Etiquetas", "Manifiesto", "Sobrecosto total", "Por bloque",
               "% del archivo", "Cifrado"],
              [[human_size(row["block_size_bytes"]), str(row["blocks"]), f"{row['tag_bytes']} B",
                f"{row['manifest_bytes']} B", f"{row['overhead_bytes']} B", f"{row['overhead_bytes_per_block']:.1f} B",
                f"{row['overhead_percent']:.4f} %", seconds(row["encrypt_seconds"])]
               for row in results["block_size_overhead"]]),
        "",
        "## Crecimiento de las envolventes",
        "Cada destinatario añade una envolvente HPKE: 32 B de clave efímera + 48 B de clave de datos sellada. "
        "El tamaño no depende del tamaño del archivo y compartir no vuelve a cifrar el contenido.",
        "",
        table(["Archivo", "Destinatarios", "Envolventes (bytes criptográficos)", "Envolventes (JSON guardado)",
               "Tiempo de sellado"],
              [[human_size(row["file_size_bytes"]), str(row["recipients"]), f"{row['grant_raw_bytes']} B",
                f"{row['grant_stored_bytes']} B", seconds(row["issue_seconds"])] for row in results["grant_growth"]]),
        "",
        "## Extremo a extremo",
        "Cliente y servidor en el mismo proceso (HTTP en memoria, disco real del servidor). "
        "La subida incluye cifrar, enviar bloques, publicar el manifiesto y la envolvente del dueño; "
        "la descarga, resolver la envolvente, bajar, verificar y descifrar.",
        "",
        table(["Tamaño", "Subida", "Velocidad", "Descarga", "Velocidad"],
              [[human_size(row["file_size_bytes"]), seconds(row["upload_seconds"]),
                speed(row["upload_mib_per_second"]), seconds(row["download_seconds"]),
                speed(row["download_mib_per_second"])] for row in results["end_to_end"]]),
        "",
    ]
    return "\n".join(sections)
