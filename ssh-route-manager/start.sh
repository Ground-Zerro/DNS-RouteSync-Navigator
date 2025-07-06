#!/bin/bash

cd /root/ssh-route-manager/ || exit 1

# Удаляем старые файлы модуля
rm -f go.mod
rm -f go.sum

# Инициализируем модуль
go mod init ssh-route-manager

# Устанавливаем зависимости
go get golang.org/x/crypto/ssh
go mod tidy

# Проверяем наличие конфигурационного файла
if [ ! -f "config.json" ]; then
    echo "Создаем пример конфигурационного файла config.json"
    cat > config.json << EOF
{
    "host": "192.168.1.1",
    "port": "22",
    "user": "root",
    "password": "password",
    "tun_name": "tun0"
}
EOF
    echo "Пожалуйста, отредактируйте config.json перед запуском программы"
    echo "Файл создан с примером конфигурации"
    exit 1
fi

echo "Запуск ssh-route-manager..."
go run ssh-route-manager.go