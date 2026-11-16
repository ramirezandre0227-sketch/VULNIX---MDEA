#!/usr/bin/env sh
# Gate de despliegue VULNIX para pipelines Linux. Uso:
#   deploy-gate.sh <artefacto> <autorizacion.jws> <clave-publica.pub>
# Sale con código != 0 (y el pipeline debe abortar) si la autorización no es válida para ESTE artefacto.
set -eu
ARTIFACT="$1"; TOKEN="$2"; PUBKEY="$3"; ISSUER="${VULNIX_ISSUER:-vulnix-local}"
vulnix-verify --token "$TOKEN" --artifact "$ARTIFACT" --public-key "$PUBKEY" --issuer "$ISSUER" || {
  echo "DESPLIEGUE BLOQUEADO por VULNIX" >&2
  exit 1
}
echo "Autorización válida para $(sha256sum "$ARTIFACT" | cut -d' ' -f1)"
