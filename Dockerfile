FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get install -y git build-essential python-is-python3 pkg-config libglib2.0-dev

RUN git clone --depth=1 --branch=v5.1.0 https://github.com/qemu/qemu /opt/qemu

WORKDIR /opt/qemu
RUN mkdir build && \
    cd build && \
    ../configure --disable-system --enable-linux-user --enable-plugins && \
    make -j16 && \
    make install

RUN mkdir /opt/tracer
WORKDIR /opt/tracer
COPY . .

RUN cd plugin && \
    make

CMD python -u tracer.py /bin/ls