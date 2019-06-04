# syntax=docker/dockerfile:experimental
FROM golang:1.12.2
ENV SSHCAPKG github.com/yahoo
COPY . /go/src/${SSHCAPKG}
WORKDIR /go/src/${SSHCAPKG}/crypki
RUN go get -v ./... && go test ./... && go build -o crypki-bin ${SSHCAPKG}/crypki/cmd/crypki


FROM debian:latest
ENV SSHCAPKG github.com/yahoo
RUN mkdir -p /var/log/crypki /opt/crypki
COPY --from=0 /go/src/${SSHCAPKG}/crypki/crypki-bin /usr/bin/

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

COPY ./crypki/docker-softhsm/init_hsm.sh /opt/crypki
COPY ./crypki/docker-softhsm/crypki.conf.sample /opt/crypki
WORKDIR /opt/crypki

RUN /bin/bash /opt/crypki/init_hsm.sh

WORKDIR /root
RUN rm -fr ${SOFTHSM2_SOURCES}

CMD ["/usr/bin/crypki-bin", "-config", "/opt/crypki/crypki-softhsm.json"]