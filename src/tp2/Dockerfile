FROM python:3.10-slim

# Outils de build (libemu-dev n'est plus dans les dépôts Debian)
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    autoconf \
    libtool \
    pkg-config \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Compiler libemu depuis les sources
RUN git clone https://github.com/buffer/libemu.git /tmp/libemu \
    && cd /tmp/libemu \
    && autoreconf -v -i \
    && ./configure --prefix=/usr/local \
    && make \
    && make install \
    && ldconfig \
    && rm -rf /tmp/libemu

# Installer pylibemu (qui dépend de libemu) + autres dépendances
RUN pip install --no-cache-dir \
    git+https://github.com/buffer/pylibemu.git \
    capstone \
    openai \
    python-dotenv

WORKDIR /app

# Uniquement ce dont tp2 a besoin :
# - src/config.py       (importé par tp2/utils/config.py via "from src.config import logging")
# - src/tp2/            (le package tp2 lui-même)
COPY src/config.py src/config.py
COPY src/tp2/ src/tp2/

# "from src.config import logging" → PYTHONPATH doit contenir /app
# "from tp2.utils.config import logger" → PYTHONPATH doit contenir /app/src
ENV PYTHONPATH="/app:/app/src"

CMD ["python", "src/tp2/main.py"]