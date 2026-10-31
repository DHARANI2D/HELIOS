#!/bin/sh
# Run once by the MSSP, not on the box: a CA for HELIOS's AI client
# certificate, and that certificate. Each box gets only helios-ca.pem (in its
# certs/ directory); HELIOS gets helios-client.pem and helios-client.key
# (HELIOS_AI_CLIENT_CERT, HELIOS_AI_CLIENT_KEY). Keep helios-ca.key offline.
#
#   ./make-certs.sh [output-dir] [days]
set -eu
out="${1:-./helios-mtls}"
days="${2:-825}"
mkdir -p "$out"
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -subj "/CN=HELIOS AI client CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$out/helios-ca.key" -out "$out/helios-ca.pem"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=HELIOS" -keyout "$out/helios-client.key" -out "$out/helios-client.csr"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > "$out/client.ext"
openssl x509 -req -in "$out/helios-client.csr" -CA "$out/helios-ca.pem" -CAkey "$out/helios-ca.key" \
  -CAcreateserial -days "$days" -extfile "$out/client.ext" -out "$out/helios-client.pem"
rm -f "$out/helios-client.csr" "$out/client.ext" "$out/helios-ca.srl"
chmod 644 "$out/helios-ca.pem" "$out/helios-client.pem"
echo "Box:    copy $out/helios-ca.pem to deploy/edge-ai/certs/ and turn on block 3 in tls.caddy"
echo "HELIOS: HELIOS_AI_CLIENT_CERT=$out/helios-client.pem HELIOS_AI_CLIENT_KEY=$out/helios-client.key"
