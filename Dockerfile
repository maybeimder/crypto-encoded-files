# Imagen única: sirve como servidor, como cliente de terminal, como interfaz web local y para las mediciones
FROM python:3.12-slim AS app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY cryptostore ./cryptostore
RUN pip install .

# Usuario sin privilegios; las carpetas de datos se crean ya con su dueño para los volúmenes
RUN useradd --create-home --uid 10001 cryptostore \
    && mkdir -p /data /users /work \
    && chown cryptostore:cryptostore /data /users /work
USER cryptostore

EXPOSE 8000 8765
CMD ["cryptostore-server", "--host", "0.0.0.0", "--port", "8000", "--data-dir", "/data"]


# Etapa de pruebas: docker build --target test -t cryptostore-test . && docker run --rm cryptostore-test
FROM app AS test
USER root
RUN pip install "pytest>=8"
COPY tests ./tests
RUN chown -R cryptostore:cryptostore /app
USER cryptostore
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
