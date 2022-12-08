#!/bin/bash
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

set -euo pipefail
umask 022

error() {
	echo "$@" >&2
	exit 1
}

SOPIN=1234
USERPIN=123456

modulepath="/usr/lib/softhsm/libsofthsm2.so" # softlink to the exact shared library based on the os arch
slot_pubkeys_path="/opt/crypki/slot_pubkeys"

user_ssh_label="user_ssh"
host_x509_label="host_x509"
host_ssh_label="host_ssh"
sign_blob_label="sign_blob"
user_ssh_keytype="EC:prime384v1"
host_x509_keytype="EC:prime384v1"
host_ssh_keytype="rsa:4096"
sign_blob_keytype="rsa:4096"
user_ssh_cipher_cmd="ec"
host_x509_cipher_cmd="ec"
host_ssh_cipher_cmd="rsa"
sign_blob_cipher_cmd="rsa"

#
# check for required binaries and libraries
#
if [ "`uname -s`" != "Linux" ]; then
	error "This only works on linux because required binaries and libraries are only available and tested on linux."
fi
p11tool="`which pkcs11-tool 2>/dev/null`"
p11tool="${p11tool:=/usr/bin/pkcs11-tool}"
if [ ! -x "${p11tool}" ]; then
	error "Can't find pkcs11-tool binary in path or /usr/bin/pkcs11-tool. Needed to configure the HSM/PKCS#11 device.
	yum -y install opensc or apt-get install opensc # (or local equivalent package)"
fi
softhsm="`which softhsm2-util 2>/dev/null`"
softhsm="${softhsm:=/usr/bin/softhsm2-util}"
if [ ! -x "${softhsm}" ]; then
	error "Can't find softhsm binary in path or /usr/bin/softhsm2-util. Needed to configure the HSM/PKCS#11 device.
	yum -y install softhsm or apt-get install softhsm # (or local equivalent package)"
fi
openssl="${openssl:=/usr/bin/openssl}"
if [ ! -x "${openssl}" ]; then
	error "Can't find openssl binary in path or /usr/bin/openssl. Needed to install openssl.
	yum -y install openssl or apt-get install openssl # (or local equivalent package)"
fi

set -e # exit if anything at all fails after here

#
# {re-}initialize slots with SO PIN
#
user_ssh_slot=`${softhsm} --init-token --slot 0 --label ${user_ssh_label} --so-pin ${SOPIN} --pin ${USERPIN} | awk '{print $NF}'`
host_x509_slot=`${softhsm} --init-token --slot 1 --label ${host_x509_label} --so-pin ${SOPIN} --pin ${USERPIN} | awk '{print $NF}'`
host_ssh_slot=`${softhsm} --init-token --slot 2 --label ${host_ssh_label} --so-pin ${SOPIN} --pin ${USERPIN} | awk '{print $NF}'`
sign_blob_slot=`${softhsm} --init-token --slot 3 --label ${sign_blob_label} --so-pin ${SOPIN} --pin ${USERPIN} | awk '{print $NF}'`

# Generate the Keys in the PKCS11 slot
${p11tool} --module ${modulepath} --pin ${USERPIN} --slot ${user_ssh_slot} --keypairgen --label ${user_ssh_label} --key-type ${user_ssh_keytype} --private
${p11tool} --module ${modulepath} --pin ${USERPIN} --slot ${host_x509_slot} --keypairgen --label ${host_x509_label} --key-type ${host_x509_keytype} --private
${p11tool} --module ${modulepath} --pin ${USERPIN} --slot ${host_ssh_slot} --keypairgen --label ${host_ssh_label} --key-type ${host_ssh_keytype} --private
${p11tool} --module ${modulepath} --pin ${USERPIN} --slot ${sign_blob_slot} --keypairgen --label ${sign_blob_label} --key-type ${sign_blob_keytype} --private

# Store the CA public keys of each PKCS11 slot.
# The public keys are useful to configure CA for PSSHCA deployment.
${p11tool} --module ${modulepath} -r --type pubkey --slot ${user_ssh_slot} --label ${user_ssh_label} -l --output-file ${slot_pubkeys_path}/${user_ssh_label}_pub.der --pin=${USERPIN}
${p11tool} --module ${modulepath} -r --type pubkey --slot ${host_x509_slot} --label ${host_x509_label} -l --output-file ${slot_pubkeys_path}/${host_x509_label}_pub.der --pin=${USERPIN}
${p11tool} --module ${modulepath} -r --type pubkey --slot ${host_ssh_slot} --label ${host_ssh_label} -l --output-file ${slot_pubkeys_path}/${host_ssh_label}_pub.der --pin=${USERPIN}
${p11tool} --module ${modulepath} -r --type pubkey --slot ${sign_blob_slot} --label ${sign_blob_label} -l --output-file ${slot_pubkeys_path}/${sign_blob_label}_pub.der --pin=${USERPIN}
openssl ${user_ssh_cipher_cmd} -inform DER -in ${slot_pubkeys_path}/${user_ssh_label}_pub.der -pubin -out ${slot_pubkeys_path}/${user_ssh_label}_pub.pem
openssl ${host_x509_cipher_cmd} -inform DER -in ${slot_pubkeys_path}/${host_x509_label}_pub.der -pubin -out ${slot_pubkeys_path}/${host_x509_label}_pub.pem
openssl ${host_ssh_cipher_cmd} -inform DER -in ${slot_pubkeys_path}/${host_ssh_label}_pub.der -pubin -out ${slot_pubkeys_path}/${host_ssh_label}_pub.pem
openssl ${sign_blob_cipher_cmd} -inform DER -in ${slot_pubkeys_path}/${sign_blob_label}_pub.der -pubin -out ${slot_pubkeys_path}/${sign_blob_label}_pub.pem

CRYPKI_CONFIG=`sed -e "s/SLOTNUM_USER_SSH/${user_ssh_slot}/g; s/SLOTNUM_HOST_X509/${host_x509_slot}/g; s/SLOTNUM_HOST_SSH/${host_ssh_slot}/g; s/SLOTNUM_SIGN_BLOB/${sign_blob_slot}/g" crypki.conf.sample`

echo "${CRYPKI_CONFIG}" > /opt/crypki/crypki-softhsm.json
