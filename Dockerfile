FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python2 \
    python-is-python2 \
    build-essential \
    libunwind-dev \
    gdb \
    git \
    libuv1-dev \
    pkg-config \
    procps \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://bootstrap.pypa.io/pip/2.7/get-pip.py | python2 && \
    pip install BitVector tqdm

COPY . /alice

ENV ALICE_HOME=/alice
ENV PATH=$PATH:/alice/bin

RUN cd /alice/alice-strace && \
    make distclean >/dev/null 2>&1 || true && \
    LIBS="-lunwind-$(uname -m) -lunwind -llzma" ./configure && \
    make -j$(nproc) && make install

RUN echo "set auto-load safe-path /" >> /root/.gdbinit

WORKDIR /alice
