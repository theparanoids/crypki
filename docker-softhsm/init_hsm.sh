#!/bin/bash
set -euo pipefail
umask 022

error() {
	echo "$@" >&2
	exit 1
}

SOPIN=1234
USERPIN=123456

#
# check for needed binaries/etc, provide "helpful" advice
#
if [ "`uname -s`" != "Linux" ]; then
	error "This only works on linux because the binaries and librarys are only available there."
fi
p11tool="`which pkcs11-tool 2>/dev/null`"
p11tool="${p11tool:=/usr/bin/pkcs11-tool}"
if [ ! -x "${p11tool}" ]; then
	error "Can't find pkcs11-tool binary in path or /usr/bin/pkcs11-tool. Needed to configure the HSM.
	yum -y install opensc # (or local equivalent rpm)"
fi
softhsm="`which softhsm2-util 2>/dev/null`"
softhsm="${softhsm:=/usr/bin/softhsm2-util}"
if [ ! -x "${softhsm}" ]; then
	error "Can't find softhsm binary in path or /usr/bin/softhsm2-util. Needed to configure the HSM.
	yum -y install softhsm # (or local equivalent rpm)"
fi

set -e # exit if anything at all fails after here

#
# {re-}initialize slots with SO PIN
#
user_ssh_slot=`${softhsm} --init-token --slot 0 --label user_ssh --so-pin ${SOPIN} --pin ${USERPIN} | awk '{print $NF}'`
host_x509_slot=`${softhsm} --init-token --slot 1 --label host_x509 --so-pin ${SOPIN} --pin ${USERPIN} | awk '{print $NF}'`
host_ssh_slot=`${softhsm} --init-token --slot 2 --label host_ssh --so-pin ${SOPIN} --pin ${USERPIN} | awk '{print $NF}'`

modulepath="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
# Generate the Keys in the PKCS11 slot
${p11tool} --module ${modulepath} --pin 123456 --slot ${user_ssh_slot} --keypairgen --label "user_ssh" --key-type rsa:4096 --private
${p11tool} --module ${modulepath} --pin 123456 --slot ${host_x509_slot} --keypairgen --label "host_x509" --key-type rsa:4096 --private
${p11tool} --module ${modulepath} --pin 123456 --slot ${host_ssh_slot} --keypairgen --label "host_ssh" --key-type rsa:4096 --private

CRYPKI_CONFIG=`sed -e "s/SLOTNUM_USER_SSH/${user_ssh_slot}/g; s/SLOTNUM_HOST_X509/${host_x509_slot}/g; s/SLOTNUM_HOST_SSH/${host_ssh_slot}/g" crypki.conf.sample`

echo "${CRYPKI_CONFIG}" > /opt/crypki/crypki-softhsm.json
