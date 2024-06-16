#!/bin/bash

REMOTE_MAIN_FILE_URL="https://raw.githubusercontent.com/Ground-Zerro/DNS-RouteSync-Navigator/main/main.py"
REMOTE_CONFIG_FILE_URL="https://raw.githubusercontent.com/Ground-Zerro/DNS-RouteSync-Navigator/main/config.ini"
REMOTE_FILTER_FILE_URL="https://raw.githubusercontent.com/Ground-Zerro/DNS-RouteSync-Navigator/main/filter.txt"
REMOTE_REQUIREMENTS_FILE_URL="https://raw.githubusercontent.com/Ground-Zerro/DNS-RouteSync-Navigator/main/requirements.txt"

INSTALL_DIR="/usr/local/bin/routesync/"
CONFIG_FILE="config.ini"
FILTER_FILE="filter.txt"
DESCRIPTION="DNS RouteSync Navigator"
SERVICE_NAME="dns-routesync-navigator"

if [ "$EUID" -ne 0 ]; then
    echo "Пожалуйста, запустите от имени администратора"
    exit 1
fi

install_python() {
    echo "Python версии 3.12 не обнаружен в системе."
    read -p "Хотите установить Python 3.12? (y/n): " choice
    case "$choice" in 
        y|Y) 
            echo "Установка Python 3.12..."
            ;;
        n|N) 
            echo "Установка прервана. Для работы приложения требуется Python версии 3.12."
            exit 1
            ;;
        *)
            echo "Некорректный выбор. Завершение."
            exit 1
            ;;
    esac
}

check_python_version() {
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    if [[ "$python_version" < "3.12" ]]; then
        install_python
    fi
}

check_service_existence() {
    if systemctl list-unit-files | grep -q "^$SERVICE_NAME.service"; then
        echo "Служба '$SERVICE_NAME' уже установлена."
        read -p "Хотите переустановить (r) или удалить (d)? (r/d): " choice
        case "$choice" in 
            r|R) reinstall_service ;;
            d|D) uninstall_service ;;
            *) echo "Некорректный выбор. Завершение." ;;
        esac
        exit 1
    fi
}

check_files_existence() {
    if [ -f "${INSTALL_DIR}main.py" ] || [ -f "${INSTALL_DIR}$CONFIG_FILE" ] || [ -f "${INSTALL_DIR}$FILTER_FILE" ]; then
        echo "Файлы уже присутствуют в указанной папке."
        read -p "Хотите переустановить (r) или удалить (d)? (r/d): " choice
        case "$choice" in 
            r|R) reinstall_service ;;
            d|D) uninstall_service ;;
            *) echo "Некорректный выбор. Завершение." ;;
        esac
        exit 1
    fi
}

install_dependencies() {
    echo "Установка зависимостей из requirements.txt..."
    pip3 install -r requirements.txt
}

check_dependencies() {
    if ! command -v pip3 &> /dev/null; then
        echo "pip3 не установлен."
        read -p "Хотите установить pip3? (y/n): " choice
        case "$choice" in 
            y|Y) 
                echo "Установка pip3..."
                apt-get update
                apt-get install -y python3-pip
                ;;
            n|N) 
                echo "Установка прервана. Для работы приложения требуется pip3."
                exit 1
                ;;
            *)
                echo "Некорректный выбор. Завершение."
                exit 1
                ;;
        esac
    fi

    if [ ! -f "requirements.txt" ]; then
        echo "Файл requirements.txt не найден."
        exit 1
    fi

    if ! pip3 install -r requirements.txt &> /dev/null; then
        echo "Некоторые зависимости отсутствуют."
        read -p "Хотите установить недостающие зависимости? (y/n): " choice
        case "$choice" in 
            y|Y) 
                install_dependencies
                ;;
            n|N) 
                echo "Установка прервана. Для работы приложения требуются определенные зависимости."
                exit 1
                ;;
            *)
                echo "Некорректный выбор. Завершение."
                exit 1
                ;;
        esac
    fi
}

pre_install_dependencies_check() {
    check_dependencies
}

install_service() {
    check_python_version

    curl -o "${INSTALL_DIR}main.py" $REMOTE_MAIN_FILE_URL
    curl -o "${INSTALL_DIR}$CONFIG_FILE" $REMOTE_CONFIG_FILE_URL
    curl -o "${INSTALL_DIR}$FILTER_FILE" $REMOTE_FILTER_FILE_URL

    chmod +x "${INSTALL_DIR}main.py"
    bash -c "cat > /etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=$DESCRIPTION
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}main.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    systemctl enable $SERVICE_NAME
    systemctl start $SERVICE_NAME

    echo "Установка и настройка службы завершены."
    echo "Файл конфигурации: ${INSTALL_DIR}$CONFIG_FILE"
    echo "Добавьте ваши домены в файл фильтра: ${INSTALL_DIR}$FILTER_FILE"
}

reinstall_service() {
    uninstall_service
    install_service
}

uninstall_service() {
    systemctl stop $SERVICE_NAME
    systemctl disable $SERVICE_NAME
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    rm -rf $INSTALL_DIR
    echo "Служба и файлы удалены."
}

pre_install_check() {
    check_service_existence
    check_files_existence
}

main() {
    pre_install_dependencies_check
    mkdir -p $INSTALL_DIR
    pre_install_check
    install_service

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl start $SERVICE_NAME

    echo "Установка и настройка службы завершены."
    echo "Файл конфигурации: ${INSTALL_DIR}$CONFIG_FILE"
    echo "Добавьте ваши домены в файл фильтра: ${INSTALL_DIR}$FILTER_FILE"
}

main
