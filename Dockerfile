FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get install -y git build-essential python-is-python3 python3-dev python3-pip pkg-config libglib2.0-dev

RUN git clone --depth=1 --branch=v5.1.0 https://github.com/qemu/qemu /opt/qemu

WORKDIR /opt/qemu
RUN mkdir build && \
    cd build && \
    ../configure --disable-system --enable-linux-user --enable-plugins && \
    make -j16 && \
    make install

RUN mkdir /opt/qtrace
WORKDIR /opt/qtrace
COPY . .

RUN cd qemu_plugin && \
    make

RUN pip3 install -e .

ENV PYTHONUNBUFFERED=True
CMD cd / && qtrace /bin/ls