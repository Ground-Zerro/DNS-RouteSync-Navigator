#!/bin/bash

set -e

if [ ! -f "config.json" ]; then
    echo "config.json not found"
    exit 1
fi

if ! command -v ipset &> /dev/null; then
    echo "ipset not installed"
    exit 1
fi

if ! command -v go &> /dev/null; then
    echo "go not installed"
    exit 1
fi

if ! ipset list test &> /dev/null; then
    ipset create test hash:ip
fi

if [ ! -f "go.mod" ]; then
    go mod init ipset-route-manager
fi

if [ ! -f "go.sum" ] || [ "main.go" -nt "go.sum" ]; then
    go mod tidy
fi

go run main.go

