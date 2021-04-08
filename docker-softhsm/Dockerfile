FROM golang:1.16.2
ENV CRYPKI_DIR /go/src/github.com/theparanoids/crypki
COPY . ${CRYPKI_DIR}
WORKDIR ${CRYPKI_DIR}
RUN go get -v ./... && go test ./... && go build -o crypki-bin ${CRYPKI_DIR}/cmd/crypki

FROM debian:sid-slim
ENV CRYPKI_DIR /go/src/github.com/theparanoids/crypki
WORKDIR /opt/crypki

COPY --from=0 ${CRYPKI_DIR}/crypki-bin /usr/bin/
COPY ./docker-softhsm/init_hsm.sh /opt/crypki
COPY ./docker-softhsm/crypki.conf.sample /opt/crypki

RUN mkdir -p /var/log/crypki /opt/crypki \
&& apt-get update \
&& apt-get install -y softhsm opensc \
&& /bin/bash -x /opt/crypki/init_hsm.sh

CMD ["/usr/bin/crypki-bin", "-config", "/opt/crypki/crypki-softhsm.json"]
