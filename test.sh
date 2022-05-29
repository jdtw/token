#!/bin/bash
set -euxo pipefail

TESTDIR="./testtmp"
KEYSET="${TESTDIR}/ks.pb"
PRIV="${TESTDIR}/priv.pb"

cleanup() {
    exit_status=$?
    rm -rf ${TESTDIR}
    exit "$exit_status"
}
trap cleanup EXIT

mkdir "${TESTDIR}"
go build -o "${TESTDIR}" ./...

echo "Creating new keyset..."
"${TESTDIR}/tokenpb" keyset init "${KEYSET}"
"${TESTDIR}/tokenpb" keyset add --subject "john" --priv-path "${PRIV}" "${KEYSET}"
"${TESTDIR}/tokenpb" keyset dump --json "${KEYSET}" | yq -P

echo "Signing and verifying a tokne..."
"${TESTDIR}/tokenpb" sign --resource "resource" "${PRIV}" | \
"${TESTDIR}/tokenpb" verify --resource "resource" "${KEYSET}" | \
"${TESTDIR}/tokenpb" parse | yq -P

echo "Tests pass!"