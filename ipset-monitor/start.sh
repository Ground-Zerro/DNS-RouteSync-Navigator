#!/bin/bash

cd /root/ipset-monitor || exit 1

# Создаем ipset Test
ipset create test hash:net

rm -f go.mod
rm -f go.sum

go mod init ipset-monitor
go mod tidy

# Запуск
go run ipset-monitor.go test /root/ipset-monitor/test-handler.sh
