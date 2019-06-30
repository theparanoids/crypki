FROM golang:1.12.6
ENV CRYPKI_PKG /src
ENV GO111MODULE on
COPY . ${CRYPKI_PKG}
WORKDIR ${CRYPKI_PKG}
RUN go get -v ./... && go test ./... && go build -o crypki-bin ${CRYPKI_PKG}/cmd/crypki


FROM debian:latest
ENV CRYPKI_PKG /src
RUN mkdir -p /var/log/crypki /opt/crypki
COPY --from=0 ${CRYPKI_PKG}/crypki-bin /usr/bin/

ENV SOFTHSM2_VERSION=2.5.0 \
    SOFTHSM2_SOURCES=/tmp/softhsm2

# build and install SoftHSM2
RUN apt-get -y update && apt-get -y install git autogen autoconf build-essential opensc libtool pkg-config libssl-dev && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/man/?? /usr/share/man/??_* && \
git clone https://github.com/opendnssec/SoftHSMv2.git ${SOFTHSM2_SOURCES}

WORKDIR ${SOFTHSM2_SOURCES}

RUN git checkout ${SOFTHSM2_VERSION} -b ${SOFTHSM2_VERSION} \
    && sh autogen.sh \
    && ./configure --prefix=/usr/local --disable-gost \
    && make \
    && make install

COPY ./docker-softhsm/init_hsm.sh /opt/crypki
COPY ./docker-softhsm/crypki.conf.sample /opt/crypki
WORKDIR /opt/crypki

RUN /bin/bash /opt/crypki/init_hsm.sh

WORKDIR /root
RUN rm -fr ${SOFTHSM2_SOURCES}

CMD ["/usr/bin/crypki-bin", "-config", "/opt/crypki/crypki-softhsm.json"]
