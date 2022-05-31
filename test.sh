#!/bin/bash
set -euxo pipefail

TESTDIR="./testtmp"
KEYSET="${TESTDIR}/ks.pb"
PRIV="${TESTDIR}/priv.pb"
PUB="${TESTDIR}/pub.pb"

cleanup() {
    exit_status=$?
    rm -rf ${TESTDIR}
    exit "$exit_status"
}
trap cleanup EXIT

mkdir "${TESTDIR}"
go build -o "${TESTDIR}" ./...

echo "Generating a new key"
"${TESTDIR}/tokenpb" gen-key --subject "jdtw" --pub "${PUB}" --priv "${PRIV}" | yq -P
"${TESTDIR}/tokenpb" dump-pub "${PUB}" | yq -P
"${TESTDIR}/tokenpb" dump-priv "${PRIV}" | yq -P

echo "Creating new keyset..."
"${TESTDIR}/tokenpb" add-key --pub "${PUB}" "${KEYSET}"
"${TESTDIR}/tokenpb" dump-keyset "${KEYSET}" | yq -P

echo "Reading from stdin..."
"${TESTDIR}/tokenpb" dump-pub < "${PUB}" | yq -P
"${TESTDIR}/tokenpb" dump-priv < "${PRIV}" | yq -P
"${TESTDIR}/tokenpb" dump-keyset < "${KEYSET}" | yq -P

echo "Signing and verifying a token..."
"${TESTDIR}/tokenpb" sign-token --resource "resource" "${PRIV}" | \
"${TESTDIR}/tokenpb" verify-token --resource "resource" "${KEYSET}" | \
"${TESTDIR}/tokenpb" parse-token | yq -P

echo "Removing a key from the keyset..."
key_id=$("${TESTDIR}/tokenpb" dump-pub --id "${PUB}")
"${TESTDIR}/tokenpb" remove-key --id "${key_id}" "${KEYSET}"
result=$("${TESTDIR}/tokenpb" dump-keyset "${KEYSET}")
test "${result}" = "{}"


echo "Tests pass!"