#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  generate-certs.sh — PKI Certificate Generation for Local Dev
#
#  Creates a minimal PKI chain:
#    Root CA → Server Cert + Client Cert
#
#  Output files (in src/main/resources/certs/):
#    server-keystore.p12  — server's private key + certificate
#    truststore.p12       — CA cert (used to verify client certs in mTLS)
#    client-keystore.p12  — client's private key + certificate (for testing)
#    client-cert.pem      — client cert in PEM format (for curl testing)
#    client-key.pem       — client key in PEM format (for curl testing)
#
#  Usage: ./generate-certs.sh
#  Requirements: keytool (JDK), openssl
# ═══════════════════════════════════════════════════════════════════

set -e

CERTS_DIR="src/main/resources/certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

PASSWORD="changeit"

echo ""
echo "══════════════════════════════════════════════"
echo "  Step 1: Create Root CA (PKI trust anchor)"
echo "══════════════════════════════════════════════"
# Generate Root CA private key and self-signed certificate
# -genkeypair    : generate a key pair
# -alias rootca  : alias in keystore
# -keyalg RSA    : algorithm
# -keysize 4096  : key size (2048+ is minimum for CA)
# -validity 3650 : 10 years
# -ext bc=ca:true : mark as CA (Basic Constraints)
keytool -genkeypair \
  -alias rootca \
  -keyalg RSA \
  -keysize 4096 \
  -validity 3650 \
  -dname "CN=Dev Root CA, OU=Security, O=Example Corp, C=VN" \
  -ext bc=ca:true \
  -keystore rootca-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -keypass "$PASSWORD"

# Export Root CA certificate (public cert)
keytool -exportcert \
  -alias rootca \
  -keystore rootca-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -file rootca.cer \
  -rfc  # PEM format

echo "✅ Root CA created"

echo ""
echo "══════════════════════════════════════════════"
echo "  Step 2: Create Server Certificate"
echo "  (signed by Root CA)"
echo "══════════════════════════════════════════════"
# Generate server key pair
keytool -genkeypair \
  -alias server \
  -keyalg RSA \
  -keysize 2048 \
  -validity 365 \
  -dname "CN=localhost, OU=Backend, O=Example Corp, C=VN" \
  -keystore server-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -keypass "$PASSWORD"

# Generate Certificate Signing Request (CSR) for server
keytool -certreq \
  -alias server \
  -keystore server-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -file server.csr

# Root CA signs the server CSR
# san=dns:localhost,ip:127.0.0.1 → Subject Alternative Names (required for modern TLS)
keytool -gencert \
  -alias rootca \
  -keystore rootca-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -infile server.csr \
  -outfile server.cer \
  -ext san=dns:localhost,ip:127.0.0.1 \
  -validity 365 \
  -rfc

# Import Root CA cert into server keystore (builds the cert chain)
keytool -importcert \
  -alias rootca \
  -keystore server-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -file rootca.cer \
  -noprompt

# Import signed server cert into server keystore
keytool -importcert \
  -alias server \
  -keystore server-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -file server.cer \
  -noprompt

echo "✅ Server certificate created and signed by Root CA"

echo ""
echo "══════════════════════════════════════════════"
echo "  Step 3: Create Truststore"
echo "  (holds Root CA cert — used by server to verify client certs in mTLS)"
echo "══════════════════════════════════════════════"
keytool -importcert \
  -alias rootca \
  -keystore truststore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -file rootca.cer \
  -noprompt

echo "✅ Truststore created with Root CA"

echo ""
echo "══════════════════════════════════════════════"
echo "  Step 4: Create Client Certificate"
echo "  (for mTLS — client proves its identity to the server)"
echo "══════════════════════════════════════════════"
keytool -genkeypair \
  -alias client \
  -keyalg RSA \
  -keysize 2048 \
  -validity 365 \
  -dname "CN=dev-client, OU=Services, O=Example Corp, C=VN" \
  -keystore client-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -keypass "$PASSWORD"

# Generate CSR for client
keytool -certreq \
  -alias client \
  -keystore client-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -file client.csr

# Root CA signs the client CSR
keytool -gencert \
  -alias rootca \
  -keystore rootca-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -infile client.csr \
  -outfile client.cer \
  -ext eku=clientAuth \  # Extended Key Usage: client authentication only
  -validity 365 \
  -rfc

# Import Root CA + signed cert into client keystore
keytool -importcert \
  -alias rootca \
  -keystore client-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -file rootca.cer \
  -noprompt

keytool -importcert \
  -alias client \
  -keystore client-keystore.p12 \
  -storetype PKCS12 \
  -storepass "$PASSWORD" \
  -file client.cer \
  -noprompt

echo "✅ Client certificate created and signed by Root CA"

echo ""
echo "══════════════════════════════════════════════"
echo "  Step 5: Export client cert/key as PEM"
echo "  (for testing with curl)"
echo "══════════════════════════════════════════════"
openssl pkcs12 \
  -in client-keystore.p12 \
  -passin pass:"$PASSWORD" \
  -nokeys \
  -out client-cert.pem

openssl pkcs12 \
  -in client-keystore.p12 \
  -passin pass:"$PASSWORD" \
  -nocerts \
  -nodes \
  -out client-key.pem

echo "✅ Client PEM files exported"

echo ""
echo "══════════════════════════════════════════════"
echo "  Cleanup intermediate files"
echo "══════════════════════════════════════════════"
rm -f server.csr server.cer client.csr client.cer rootca-keystore.p12

echo ""
echo "🎉 PKI setup complete!"
echo ""
echo "Files in $CERTS_DIR:"
echo "  server-keystore.p12  → server TLS certificate + key"
echo "  truststore.p12       → CA cert for verifying client certs (mTLS)"
echo "  client-keystore.p12  → client certificate + key"
echo "  client-cert.pem      → client cert (PEM, for curl)"
echo "  client-key.pem       → client key (PEM, for curl)"
echo "  rootca.cer           → Root CA public cert"
echo ""
echo "Test with curl (mTLS):"
echo "  curl --cacert rootca.cer \\"
echo "       --cert client-cert.pem \\"
echo "       --key  client-key.pem \\"
echo "       https://localhost:8443/api/public/health"
