# Copyright 2023 Yahoo Inc.
# Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
FROM cgr.dev/chainguard/busybox:latest
ENTRYPOINT ["/usr/bin/crypki"]
COPY crypki /usr/bin

