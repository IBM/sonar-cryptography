#!/bin/sh

url=https://ciphersuite.info/api/cs/
status_code=$(curl -s -o /dev/null -w "%{http_code}" "$url")

if [ "$status_code" -eq 200 ]; then
    curl "$url" -o ciphersuites.json
    echo "Successfully processed $url"
    python3 creatCipherSuiteClass.py
else
    echo "Failed to process $url (Status code: $status_code)"
fi