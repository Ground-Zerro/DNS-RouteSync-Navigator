import socket
import telnetlib3
import asyncio
import configparser
from dnslib import DNSRecord


# Функция чтения настроек
def read_config(filename):
    config = configparser.ConfigParser()
    config.read(filename)
    return config['config']


# Функция для отправки DNS запросов к публичному DNS серверу
def send_dns_query(data, public_dns):
    dns_server = public_dns  # Публичный DNS
    dns_port = 53

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Создаем сокет для UDP соединения

    client_socket.sendto(data, (dns_server, dns_port))  # Отправляем запрос

    response, _ = client_socket.recvfrom(1024)  # Получаем ответ
    return response


# Функция для обработки полученного ответа
def process_dns_response(dns_response):
    global fdomain, fdata
    try:
        dns_record = DNSRecord.parse(dns_response)
        for r in dns_record.rr:
            if r.rtype == 1:  # A record
                fdomain = r.rname  # Домен в переменную
                fdata = r.rdata  # IP-адрес домена в переменную
                print(f"Resolved {fdomain} to {fdata}")  # Отладочное сообщение домену сопоставлен IP-адрес
                break
    except Exception as e:
        print(f"Error processing DNS response: {e}")


# Поиск DNS имени в фильтре
def compare_dns(domain, domain_file):
    with open(domain_file, 'r', encoding='utf-8-sig') as file:
        for line in file:
            filter_domain = line.strip()  # Удаляем символы новой строки и лишние пробелы
            name_parts = str(domain).rstrip('.').split('.')  # Разделяем DNS имя на части и убираем точку в конце
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


# Отправка роутеру команды на добавление статического маршрута для IP по Telnet
async def cli_command(fdata, router_ip, telnet_port, login, password, eth_id):
    try:
        command = f"ip route {str(fdata).rstrip('.')}/32 {eth_id}"  # Формируем команду
        reader, writer = await telnetlib3.open_connection(router_ip, telnet_port)
        rules = [('Login:', login), ('Password:', password), ('(config)>', command), ('Network:', 'exit')]
        ruleiter = iter(rules)
        expect, send = next(ruleiter)
        while True:
            outp = await reader.read(1024)
            if not outp:
                break

            if expect in outp:
                writer.write(send)
                writer.write('\r\n')
                try:
                    expect, send = next(ruleiter)
                except StopIteration:
                    break
            # раскоментируйте строку ниже, чтобы выводить все выходные данные сервера
            # print(outp, flush=True)
        # EOF
        print()

    except Exception as e:
        print(f"Error occurred: {e}")


# Основная функция
def main():
    config_data = read_config('config.ini')

    domain_file = config_data['domain_file']
    router_ip = config_data['router_ip']
    telnet_port = int(config_data['telnet_port'])
    login = config_data['login']
    password = config_data['password']
    eth_id = config_data['eth_id']
    server_address = config_data['server_address']
    server_port = int(config_data['server_port'])
    public_dns = config_data['public_dns']

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Создаем сокет для UDP соединения

    server_socket.bind((server_address, server_port))  # Привязываем сервер к адресу и порту
    print(
        'DNS Server listening on {}:{}'.format(server_address, server_port))  # Отладочное сообщение DNS сервер запущен

    while True:
        data, client_address = server_socket.recvfrom(1024)  # Получаем данные от клиента
        # print(
        #    f"Received request from client at {client_address[0]}")  # Отладочное сообщение - получен запрос от клиента

        dns_response = send_dns_query(data, public_dns)  # Обработка DNS запроса

        process_dns_response(dns_response)  # Обработка полученного ответа

        server_socket.sendto(dns_response, client_address)  # Отправляем ответ клиенту
        # print(f"Sent response to client at {client_address[0]}")  # Отладочное сообщение - IP отправлен клиенту

        match = compare_dns(fdomain, domain_file)  # Сравнение DNS имени из запроса с фильтром
        if match:
            print(f"{fdomain} найден в фильтре")  # Отладочное сообщение
            asyncio.run(cli_command(fdata, router_ip, telnet_port, login, password,
                                    eth_id))  # Отправляем статический маршрут роутеру с IP-адресом домена из фильтра
        # else:
        #     print(f"Нет совпадения {fdomain}")  # Отладочное сообщение


if __name__ == "__main__":
    main()
