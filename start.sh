#!/bin/bash

SERVICE_NAME="RouterSyncNavigator.service"
UNIT_FILE_PATH="/etc/systemd/system/$SERVICE_NAME"
SCRIPT_DIR="$(dirname "$(realpath "$0")")"  # Директория, в которой находится сам скрипт

# Проверка наличия необходимых файлов
if [ ! -f "$SCRIPT_DIR/config.ini" ] || [ ! -f "$SCRIPT_DIR/main.py" ]; then
    echo "Не найдены файлы config.ini и main.py, необходимые для работы скрипта."
    read -p "Скачать Router Sync Navigator с GitHub? (y/n): " download_choice

    if [ "$download_choice" = "y" ]; then
        echo "Скачивание файлов..."

        # Скачивание файлов
        curl -L -o "$SCRIPT_DIR/main.py" "https://github.com/Ground-Zerro/DNS-RouteSync-Navigator/raw/main/main.py"
        curl -L -o "$SCRIPT_DIR/config.ini" "https://github.com/Ground-Zerro/DNS-RouteSync-Navigator/raw/main/config.ini"
        curl -L -o "$SCRIPT_DIR/filter.txt" "https://github.com/Ground-Zerro/DNS-RouteSync-Navigator/raw/main/filter.txt"

        if [ $? -eq 0 ]; then
            echo "Router Sync Navigator загружен, перед запуском укажите настройки в config.ini и домены в filter.txt."
        else
            echo "Ошибка при загрузке файлов. Проверьте ваше соединение с интернетом и попробуйте снова."
            exit 1
        fi
    else
        exit 1
    fi
fi

# Функция для создания файла юнита
create_unit_file() {
    # Установка прав 777 на файл main.py перед созданием файла юнита
    chmod 777 "$SCRIPT_DIR/main.py"

    sudo bash -c "cat > $UNIT_FILE_PATH" << EOF
[Unit]
Description=Router Sync Navigator Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SCRIPT_DIR/main.py
WorkingDirectory=$SCRIPT_DIR
Restart=always
Environment=PYTHONUNBUFFERED=1
StandardError=file:$SCRIPT_DIR/work.log

[Install]
WantedBy=multi-user.target
EOF
}

# Функция для замены путей в файле main.py и config.ini
update_main_py() {
    # Замена путей в main.py
    sed -i "s|read_config('config.ini')|read_config('$SCRIPT_DIR/config.ini')|" "$SCRIPT_DIR/main.py"

    # Проверка и замена в config.ini, если строки нет
    if ! grep -q "domain_file = $SCRIPT_DIR/" "$SCRIPT_DIR/config.ini"; then
        sed -i "s|domain_file = |domain_file = $SCRIPT_DIR/|" "$SCRIPT_DIR/config.ini"
    fi
}

# Функция для проверки статуса службы
check_status() {
    systemctl is-active --quiet $SERVICE_NAME
}

# Функция для управления службой
manage_service() {
    if check_status; then
        echo "Служба $SERVICE_NAME работает."
        echo "Что вы хотите сделать?"
        echo "1. Остановить службу"
        echo "2. Перезапустить службу"
        echo "3. Ничего не делать"
        read -p "Выберите опцию (1/2/3): " option

        case $option in
            1)
                sudo systemctl stop $SERVICE_NAME
                if [ $? -eq 0 ]; then
                    echo "Служба полностью остановлена."
                else
                    echo "Ошибка при остановке службы."
                fi
                ;;
            2)
                sudo systemctl restart $SERVICE_NAME
                if [ $? -eq 0 ]; then
                    echo "Служба успешно перезапущена."
                else
                    echo "Ошибка при перезапуске службы."
                fi
                ;;
            3)
                ;;
            *)
                echo "Некорректный выбор. Выберите 1, 2 или 3."
                ;;
        esac
    else
        echo "Служба RouterSyncNavigator:"
        echo "1. Запустить"
        echo "2. Удалить"
        read -p "Выберите опцию (1/2): " option

        case $option in
            1)
                sudo systemctl start $SERVICE_NAME > /dev/null 2>&1
                if [ $? -eq 0 ]; then
                    echo "Служба $SERVICE_NAME запущена."
                else
                    echo "Ошибка при запуске службы $SERVICE_NAME."
                fi
                ;;
            2)
                sudo systemctl stop $SERVICE_NAME
                sudo systemctl disable $SERVICE_NAME
                sudo rm -f $UNIT_FILE_PATH
                sudo systemctl daemon-reload
                echo "Служба $SERVICE_NAME удалена из системы."
                ;;
            *)
                echo "Некорректный выбор. Выберите 1 или 2."
                ;;
        esac
    fi
}

# Проверка существования файла юнита
if [ ! -f "$UNIT_FILE_PATH" ]; then
    echo "RouterSyncNavigator:"
    echo "1. Установить как системную службу"
    echo "2. Запустить в Python"
    echo "3. Ничего не делать"
    read -p "Выберите опцию (1/2/3): " option

    case $option in
        1)
            create_unit_file
            sudo systemctl daemon-reload > /dev/null 2>&1
            sudo systemctl enable $SERVICE_NAME > /dev/null 2>&1
            sudo systemctl start $SERVICE_NAME > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "Служба $SERVICE_NAME установлена и запущена."
            else
                echo "Ошибка при запуске службы $SERVICE_NAME."
            fi
            ;;
        2)
            /usr/bin/python3 "$SCRIPT_DIR/main.py"
            if [ $? -eq 0 ]; then
                echo "Скрипт main.py выполнен."
            else
                echo "Ошибка при выполнении скрипта main.py."
            fi
            ;;
        3)
            ;;
        *)
            echo "Некорректный выбор. Выберите 1, 2 или 3."
            ;;
    esac
else
    # Если файл юнита существует, просто убедитесь, что служба запущена
    manage_service
fi

# Обновление путей в файле main.py
update_main_py
