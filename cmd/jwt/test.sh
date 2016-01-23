#!/bin/bash

set -e

go build

NOW=$(date +%s)

for i in ../../testdata/*.pem; do
  ENC=$(echo '{"iss": "foo", "nbf": '$NOW'}' | ./jwt -enc -k $i)
  DEC=$(./jwt -dec -k $i <<< "$ENC"|jq -C '.')

  echo -e "-------------------------------------\nKEY: $i\nENCODED:\n\n$ENC\n\nDECODED:\n\n$DEC"

done
