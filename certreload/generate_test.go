// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package certreload

//go:generate certstrap init --passphrase "" --common-name "ca" --years 80
//go:generate certstrap request-cert --passphrase "" --common-name client
//go:generate certstrap sign client --passphrase "" --CA ca --years 80
//go:generate mkdir -p ./testdata
//go:generate mv -f ./out/ca.crt ./out/client.crt ./out/client.key ./testdata
//go:generate rm -rf ./out
