#!/bin/bash

# Улучшенный обработчик для тестирования ipset мониторинга

IP="$1"
IPSET="$2"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
LOGFILE="/root/ipset-monitor/ipset-monitor.log"

# Проверяем аргументы
if [ -z "$IP" ] || [ -z "$IPSET" ]; then
    echo "Usage: $0 <ip_address> <ipset_name>"
    exit 1
fi

# Создаем директорию для логов если не существует
mkdir -p "$(dirname "$LOGFILE")"

# Логируем событие
echo "[$TIMESTAMP] IP: $IP добавлен в ipset: $IPSET" >> "$LOGFILE"

# Выводим на консоль
echo "[$TIMESTAMP] Handler called:"
echo "  IP Address: $IP"
echo "  IPSet Name: $IPSET"

# Дополнительные действия (примеры):
# 1. Уведомление в системный журнал
logger "IPSet Monitor: IP $IP added to set $IPSET"

# 2. Отправка уведомления (раскомментируйте при необходимости)
# curl -X POST "https://api.telegram.org/bot<TOKEN>/sendMessage" \
#      -d "chat_id=<CHAT_ID>" \
#      -d "text=New IP $IP added to ipset $IPSET"

# 3. Дополнительная проверка IP
# whois "$IP" >> "$LOGFILE"

# 4. Добавление в дополнительные правила фаервола
# iptables -A INPUT -s "$IP" -j DROP

echo "Handler completed successfully"
exit 0