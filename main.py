import asyncio
import configparser
import socket
import time

import asyncssh
import telnetlib3
from dnslib import DNSRecord

# Простая реализация кэша для хранения IP-адресов, DNS имен и времени их добавления
ip_cache_data = {}
dns_cache_data = {}


# Читаем конфиг
def read_config(filename):
    config = configparser.ConfigParser()
    try:
        config.read(filename)
        print(f"Файл конфигурации {filename} загружен.")
        return config['RouterSyncNavigator']
    except Exception as e:
        print(f"Ошибка загрузки файла конфигурации {filename}: {e}")
        return None


# Функция для отправки DNS запросов к публичному DNS серверу
def send_dns_query(data, public_dns):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Создаем сокет для UDP соединения
    client_socket.sendto(data, (public_dns, 53))  # Отправляем запрос
    response, _ = client_socket.recvfrom(1024)  # Получаем ответ
    return response


# Функция обработки полученного ответа
def process_dns_response(dns_response):
    resolved_addresses = []
    domain = ""
    try:
        dns_record = DNSRecord.parse(dns_response)
        for r in dns_record.rr:
            if r.rtype == 1:  # A record
                resolved_addresses.append(r.rdata)
                domain = r.rname
                print(f"Resolved {r.rname} to {r.rdata}")  # Отладочное сообщение о разрешенном домене и IP-адресе
    except Exception as e:
        print(f"Error processing DNS response: {e}")
    return domain, resolved_addresses


# Функция кэширования DNS имен для снижения частоты обращения к DNS серверу
def dns_cache(domain, resolved_addresses):
    global dns_cache_data
    ttl = 60  # Время жизни DNS имени в кэше в секундах
    current_time = time.time()
    if domain in dns_cache_data:
        if current_time - dns_cache_data[domain]['timestamp'] <= ttl:  # Проверяем время жизни записи в кэше
            return dns_cache_data[domain]['resolved_addresses']  # Возвращаем ранее разрешенные IP-адреса
        else:
            del dns_cache_data[domain]  # Удаляем запись из кэша, если время жизни истекло
    dns_cache_data[domain] = {'resolved_addresses': resolved_addresses, 'timestamp': current_time}  # Добавляем в кэш
    return resolved_addresses


# Поиск DNS имени в фильтре
def compare_dns(f_domain, domain_file):
    with open(domain_file, 'r', encoding='utf-8-sig') as file:
        for line in file:
            filter_domain = line.strip()  # Удаляем символы новой строки и лишние пробелы
            name_parts = str(f_domain).rstrip('.').split('.')  # Разделяем DNS имя на части и убираем точку в конце
            filter_domain_parts = filter_domain.split('.')  # Разделяем домен на части
            if len(name_parts) < len(filter_domain_parts):
                continue  # Пропускаем, если DNS имя имеет меньше частей, чем домен
            match = True
            for i in range(-1, -len(filter_domain_parts) - 1, -1):  # Проходимся в обратном порядке по частям домена
                if name_parts[i] != filter_domain_parts[i]:
                    match = False
                    break
            if match:
                return True
    return False


# SSH только для keenetic CLI
async def send_commands_via_ssh(router_ip, ssh_port, login, password, commands):
    try:
        async with asyncssh.connect(router_ip, port=ssh_port, username=login, password=password,
                                    known_hosts=None) as conn:
            for command in commands:
                result = await conn.run(command)
                # print(result.stdout, end='')  # Отладочное сообщение
                if result.stderr:
                    print(result.stderr, end='')

    except asyncssh.Error as e:
        print(f"Error occurred: {e}")


# Telnet только для keenetic CLI
async def send_commands_via_telnet(router_ip, router_port, login, password, commands):
    try:
        reader, writer = await telnetlib3.open_connection(router_ip, router_port)
        rules = [('Login:', login), ('Password:', password), ('(config)>', None)]
        ruleiter = iter(rules)
        expect, send = next(ruleiter)
        while True:
            outp = await reader.read(1024)
            if not outp:
                break

            if expect in outp:
                if send is not None:
                    writer.write(send)
                    writer.write('\r\n')
                try:
                    expect, send = next(ruleiter)
                except StopIteration:
                    break
            # print(outp, flush=True)  # Отладочное сообщение
        for command in commands:
            writer.write(command)
            writer.write('\r\n')

    except Exception as e:
        print(f"Error occurred: {e}")


# Функция кэширования IP-адресов для снижения частоты обращения к роутеру
def ip_cache(address):
    global ip_cache_data
    ttl = 10800  # Время жизни IP в кэше в секундах
    current_time = time.time()
    if address in ip_cache_data:
        if current_time - ip_cache_data[address] <= ttl:  # Проверяем время жизни записи в кэше
            return True  # IP есть в кэше и он еще не истек, возвращаем True
        else:
            del ip_cache_data[address]  # IP есть в кэше, но время его жизни истекло, удаляем запись
    return False  # IP-адреса нет в кэше или время его жизни истекло, возвращаем False


# Основная функция
async def main():
    config_data = read_config('config.ini')  # Имя конфиг-файла

    router_ip = config_data['router_ip']  # IP или DDNS имя роутера
    router_port = int(config_data['router_port'])  # Порт подключения к роутеру
    login = config_data['login']  # Логин роутера
    password = config_data['password']  # Пароль роутера
    connection_type = config_data['connection_type']  # Подключение к роутеру по Telnet или SSH
    eth_id = config_data['eth_id']  # Шлюз или имя интерфейса для редиректа IP домена из фильтра
    domain_file = config_data['domain_file']  # Файл с доменами для фильтрации
    public_dns = config_data['public_dns']  # Публичный DNS для разрешения IP-адресов доменных имен
    server_ip = config_data['server_ip']  # IP DNS сервера (на этой машине)
    server_port = int(config_data['server_port'])  # Порт DNS сервера (на этой машине)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Создаем сокет для UDP соединения

    server_socket.bind((server_ip, server_port))  # Привязываем сервер к адресу и порту
    print('DNS Server listening on {}:{}'.format(server_ip, server_port))  # Отладочное сообщение - сервер запущен

    while True:
        data, client_address = server_socket.recvfrom(1024)  # Получаем данные от клиента

        dns_response = send_dns_query(data, public_dns)  # Обработка DNS запроса

        f_domain, resolved_addresses = process_dns_response(dns_response)  # Обработка полученного ответа

        server_socket.sendto(dns_response, client_address)  # Отправляем ответ клиенту

        match = compare_dns(f_domain, domain_file)  # Проверяем совпадение DNS имени с фильтром
        if match:
            for address in resolved_addresses:  # Проверяем наличие IP-адресов в кэше
                if not ip_cache(str(address).rstrip('.')):  # Если IP нет в кэше, добавляем статический маршрут
                    commands = [f"ip route {str(address).rstrip('.')}/32 {eth_id}" for address in resolved_addresses]
                    commands.append("exit")
                    print(f"{f_domain} найден в фильтре, добавляем маршрут")  # Отладочное сообщение
                    ip_cache_data[str(address).rstrip('.')] = time.time()  # Добавляем IP в кэш
                    if connection_type == 'ssh':  # Добавление статического маршрута по SHH
                        await send_commands_via_ssh(router_ip, router_port, login, password, commands)
                    elif connection_type == 'telnet':  # Добавление статического маршрута по telnet
                        await send_commands_via_telnet(router_ip, router_port, login, password, commands)
                else:
                    print(f"Маршрут к {f_domain} был добавлен ранее")  # Отладочное сообщение


if __name__ == "__main__":
    asyncio.run(main())
