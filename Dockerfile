FROM ubuntu:20.04 AS build

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get install -y git build-essential python-is-python3 python3-dev python3-pip pkg-config libglib2.0-dev

RUN git clone --depth=1 --branch=v5.1.0 https://github.com/qemu/qemu /opt/qemu

WORKDIR /opt/qemu
RUN mkdir build && \
    cd build && \
    ../configure --disable-system --enable-linux-user --enable-plugins --target-list=x86_64-linux-user && \
    make -j$(nproc) && \
    make install

RUN mkdir /opt/qtrace
WORKDIR /opt/qtrace

COPY qemu_plugin ./qemu_plugin

RUN cd qemu_plugin && \
    make

COPY setup.py .
COPY qtrace ./qtrace

RUN python setup.py bdist_wheel

CMD ["cp", "-r", "dist", "/dist"]

FROM ubuntu:20.04 AS test

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get install -y gdb python-is-python3 python3-dev python3-pip

RUN pip install pytest

COPY --from=build /opt/qtrace/dist /tmp/dist
RUN pip install /tmp/dist/qtrace-*.whl

COPY tests /tests

COPY docker-entrypoint.sh .

CMD ./docker-entrypoint.sh
