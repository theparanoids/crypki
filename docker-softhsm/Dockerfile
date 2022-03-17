# Copyright 2021 Yahoo.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.16.2
ENV CRYPKI_DIR /go/src/github.com/theparanoids/crypki
COPY . ${CRYPKI_DIR}
WORKDIR ${CRYPKI_DIR}
RUN go get -v ./... && go test ./... && go build -o crypki-bin ${CRYPKI_DIR}/cmd/crypki && \
    go build -o gen-cacert ${CRYPKI_DIR}/cmd/gen-cacert

FROM debian:sid-slim
ENV CRYPKI_DIR /go/src/github.com/theparanoids/crypki
WORKDIR /opt/crypki

COPY --from=0 ${CRYPKI_DIR}/crypki-bin /usr/bin/
COPY --from=0 ${CRYPKI_DIR}/gen-cacert /usr/bin/
COPY ./docker-softhsm/init_hsm.sh /opt/crypki
COPY ./docker-softhsm/crypki.conf.sample /opt/crypki

RUN mkdir -p /var/log/crypki /opt/crypki /opt/crypki/slot_pubkeys \
&& apt-get update \
&& apt-get install -y softhsm opensc openssl \
&& /bin/bash -x /opt/crypki/init_hsm.sh

CMD ["/usr/bin/crypki-bin", "-config", "/opt/crypki/crypki-softhsm.json"]
