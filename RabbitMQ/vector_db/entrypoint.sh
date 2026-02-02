#!/bin/sh

sed 's/%CHROMA_AUTH_TOKEN_TRANSPORT_HEADER%/'$CHROMA_AUTH_TOKEN_TRANSPORT_HEADER'/g' /opt/bitnami/envoy/conf/envoy.yaml > /tmp/envoy_temp.yaml

if [ $CHROMA_AUTH_TOKEN_TRANSPORT_HEADER = "Authorization" ]; then
  sed -i 's/%CHROMA_SERVER_AUTHN_CREDENTIALS%/Bearer '$CHROMA_SERVER_AUTHN_CREDENTIALS'/g' /tmp/envoy_temp.yaml
else
  sed -i 's/%CHROMA_SERVER_AUTHN_CREDENTIALS%/'$CHROMA_SERVER_AUTHN_CREDENTIALS'/g' /tmp/envoy_temp.yaml
fi

cat /tmp/envoy_temp.yaml

/opt/bitnami/envoy/bin/envoy -c /tmp/envoy_temp.yaml