# Mediciones

Generado por `cryptostore-bench` el 2026-11-19 11:07. Promedio de 3 repeticiones. Python 3.13.18, Linux x86_64, procesador: x86_64.

## Tiempo de cifrado y descifrado
Bloques de 1 MiB, en memoria (sin red). El descifrado incluye verificar la firma, las huellas de cada bloque y la etiqueta AEAD antes de entregar el archivo.

| Tamaño | Bloques | Cifrado | Velocidad | Verificación + descifrado | Velocidad |
|---:|---:|---:|---:|---:|---:|
| 0 B | 1 | 0.75 ms | — | 0.78 ms | — |
| 1 KiB | 1 | 0.26 ms | — | 0.77 ms | — |
| 1 MiB | 1 | 3.35 ms | 298 MiB/s | 4.21 ms | 237 MiB/s |
| 10 MiB | 10 | 28.96 ms | 345 MiB/s | 30.86 ms | 324 MiB/s |
| 50 MiB | 50 | 121.80 ms | 411 MiB/s | 124.33 ms | 402 MiB/s |
| 100 MiB | 100 | 245.68 ms | 407 MiB/s | 258.24 ms | 387 MiB/s |

## Sobrecosto por bloque
Archivo de 100 MiB. Sobrecosto = etiqueta de 16 B por bloque + manifiesto (que lleva la huella de cada bloque). El nonce y los datos asociados no se almacenan.

| Tamaño de bloque | Bloques | Etiquetas | Manifiesto | Sobrecosto total | Por bloque | % del archivo | Cifrado |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 KiB | 1600 | 25600 B | 107791 B | 133391 B | 83.4 B | 0.1272 % | 227.58 ms |
| 256 KiB | 400 | 6400 B | 27392 B | 33792 B | 84.5 B | 0.0322 % | 219.24 ms |
| 1 MiB | 100 | 1600 B | 7293 B | 8893 B | 88.9 B | 0.0085 % | 221.08 ms |
| 4 MiB | 25 | 400 B | 2268 B | 2668 B | 106.7 B | 0.0025 % | 206.82 ms |

## Crecimiento de las envolventes
Cada destinatario añade una envolvente HPKE: 32 B de clave efímera + 48 B de clave de datos sellada. El tamaño no depende del tamaño del archivo y compartir no vuelve a cifrar el contenido.

| Archivo | Destinatarios | Envolventes (bytes criptográficos) | Envolventes (JSON guardado) | Tiempo de sellado |
|---:|---:|---:|---:|---:|
| 1 KiB | 1 | 80 B | 299 B | 0.40 ms |
| 1 KiB | 2 | 160 B | 598 B | 0.27 ms |
| 1 KiB | 3 | 240 B | 897 B | 0.39 ms |
| 1 KiB | 4 | 320 B | 1196 B | 0.54 ms |
| 1 KiB | 5 | 400 B | 1495 B | 0.62 ms |
| 100 MiB | 1 | 80 B | 299 B | 0.18 ms |
| 100 MiB | 2 | 160 B | 598 B | 0.25 ms |
| 100 MiB | 3 | 240 B | 897 B | 0.38 ms |
| 100 MiB | 4 | 320 B | 1196 B | 0.48 ms |
| 100 MiB | 5 | 400 B | 1495 B | 0.62 ms |

## Extremo a extremo
Cliente y servidor en el mismo proceso (HTTP en memoria, disco real del servidor). La subida incluye cifrar, enviar bloques, publicar el manifiesto y la envolvente del dueño; la descarga, resolver la envolvente, bajar, verificar y descifrar.

| Tamaño | Subida | Velocidad | Descarga | Velocidad |
|---:|---:|---:|---:|---:|
| 1 KiB | 20.24 ms | — | 9.04 ms | — |
| 1 MiB | 27.07 ms | 37 MiB/s | 11.50 ms | 87 MiB/s |
| 10 MiB | 104.46 ms | 96 MiB/s | 65.23 ms | 153 MiB/s |
| 100 MiB | 1.05 s | 95 MiB/s | 613.67 ms | 163 MiB/s |
