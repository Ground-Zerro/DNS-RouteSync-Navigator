import asyncio
import configparser
import logging
import socket
import time
from typing import Tuple, List, Optional

import asyncssh
import telnetlib3
from cachetools import TTLCache
from dnslib import DNSRecord, DNSError

# Настройка логгирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Кэш для хранения IP-адресов и DNS имен
ip_cache_data = TTLCache(maxsize=1000, ttl=10800)  # Кэш IP адресов с TTL 3 часа
dns_cache_data = TTLCache(maxsize=1000, ttl=60)    # Кэш DNS имен с TTL 1 минута


# Читаем конфиг
def read_config(filename: str) -> Optional[configparser.SectionProxy]:
    config = configparser.ConfigParser()
    try:
        config.read(filename)
        logging.info(f"Файл конфигурации {filename} загружен.")
        return config['RouterSyncNavigator']
    except KeyError:
        logging.error(f"Секция 'RouterSyncNavigator' отсутствует в файле конфигурации {filename}.")
        return None
    except Exception as e:
        logging.error(f"Ошибка загрузки файла конфигурации {filename}: {e}")
        return None


# Функция для отправки DNS запросов к публичному DNS серверу
async def send_dns_query(data: bytes, public_dns: str) -> Optional[bytes]:
    loop = asyncio.get_event_loop()
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5)  # Устанавливаем тайм-аут на 5 секунд
    try:
        await loop.run_in_executor(None, client_socket.sendto, data, (public_dns, 53))
        response, _ = await loop.run_in_executor(None, client_socket.recvfrom, 1024)
        return response
    except socket.timeout:
        logging.warning(f"Тайм-аут при отправке DNS запроса к {public_dns}")
        return None
    except Exception as e:
        logging.error(f"Ошибка отправки DNS запроса: {e}")
        return None
    finally:
        client_socket.close()


# Функция обработки ответа от DNS сервера
def process_dns_response(dns_response: bytes) -> Tuple[str, List[str]]:
    resolved_addresses = []
    domain = ""
    try:
        dns_record = DNSRecord.parse(dns_response)
        for r in dns_record.rr:
            if r.rtype == 1:  # A record
                resolved_addresses.append(str(r.rdata))
                domain = str(r.rname)
                logging.info(f"Resolved {r.rname} to {r.rdata}")
    except DNSError as e:
        logging.error(f"Ошибка обработки DNS ответа: {e}")
    return domain, resolved_addresses


# Функция кэширования DNS имен для снижения частоты обращения к DNS серверу
def dns_cache(domain: str, resolved_addresses: List[str]) -> List[str]:
    if domain in dns_cache_data:
        return dns_cache_data[domain]
    dns_cache_data[domain] = resolved_addresses
    return resolved_addresses


# Поиск DNS имени в фильтре
def compare_dns(f_domain: str, domain_file: str) -> bool:
    try:
        with open(domain_file, 'r', encoding='utf-8-sig') as file:
            for line in file:
                filter_domain = line.strip()
                name_parts = f_domain.rstrip('.').split('.')
                filter_domain_parts = filter_domain.split('.')
                if len(name_parts) < len(filter_domain_parts):
                    continue
                match = all(name_parts[i] == filter_domain_parts[i]
                            for i in range(-1, -len(filter_domain_parts) - 1, -1))
                if match:
                    return True
    except Exception as e:
        logging.error(f"Ошибка сравнения DNS: {e}")
    return False


# SSH только для keenetic CLI
async def send_commands_via_ssh(router_ip: str, ssh_port: int, login: str, password: str, commands: List[str]) -> None:
    try:
        conn = await asyncssh.connect(router_ip, port=ssh_port, username=login, password=password, known_hosts=None)
        for command in commands:
            result = await conn.run(command)
            if result.stderr:
                logging.error(result.stderr, end='')
    except asyncssh.Error as e:
        logging.error(f"Ошибка при выполнении команд через SSH: {e}")


# Telnet только для keenetic CLI ==ПРОВЕРИТЬ!! Возможно поломал пока ковырял SSH...==
async def send_commands_via_telnet(router_ip: str, router_port: int, login: str, password: str,
                                   commands: List[str]) -> None:
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
        for command in commands:
            writer.write(command)
            writer.write('\r\n')
    except Exception as e:
        logging.error(f"Ошибка при выполнении команд Telnet: {e}")


# Функция кэширования IP-адресов для снижения частоты обращения к роутеру
def ip_cache(address: str) -> bool:
    return address in ip_cache_data


# Основная функция
async def main() -> None:
    config_data = read_config('config.ini')
    if not config_data:
        return

    try:
        router_ip = config_data['router_ip']
        router_port = int(config_data['router_port'])
        login = config_data['login']
        password = config_data['password']
        connection_type = config_data['connection_type']
        eth_id = config_data['eth_id']
        domain_file = config_data['domain_file']
        public_dns = config_data['public_dns']
        server_ip = config_data['server_ip']
        server_port = int(config_data['server_port'])

    except KeyError as e:
        logging.error(f"Ошибка чтения параметров конфигурации: отсутствует ключ {e}")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.settimeout(10)  # Тайм-аут  для сервера
    loop = asyncio.get_event_loop()
    server_socket.bind((server_ip, server_port))
    logging.info(f'DNS сервер запущен {server_ip}:{server_port}')

    async def handle_client(data: bytes, client_address: Tuple[str, int]) -> None:
        dns_response = await send_dns_query(data, public_dns)
        if dns_response:
            f_domain, resolved_addresses = process_dns_response(dns_response)
            server_socket.sendto(dns_response, client_address)
            match = compare_dns(f_domain, domain_file)
            if match:
                for address in resolved_addresses:
                    if not ip_cache(address.rstrip('.')):
                        commands = [f"ip route {address.rstrip('.')}/32 {eth_id}" for address in resolved_addresses]
                        logging.info(f"домен {f_domain} найден в фильтре - добавляем маршрут для него")
                        ip_cache_data[address.rstrip('.')] = time.time()
                        if connection_type == 'ssh':
                            await send_commands_via_ssh(router_ip, router_port, login, password, commands)
                        elif connection_type == 'telnet':
                            await send_commands_via_telnet(router_ip, router_port, login, password, commands)
                    else:
                        remaining_ttl = int((ip_cache_data[address.rstrip('.')] + 10800 - time.time()) / 60)
                        logging.info(f"Маршрут к {f_domain} есть в кэше, оставшееся время жизни: {remaining_ttl} минут")

    async def recvfrom_loop():
        while True:
            try:
                data, client_address = await loop.run_in_executor(None, server_socket.recvfrom, 1024)
                asyncio.create_task(handle_client(data, client_address))
            except socket.timeout:
                continue
            except Exception as E:
                logging.error(f"Ошибка в основной петле: {E}")

    try:
        await recvfrom_loop()
    finally:
        server_socket.close()

if __name__ == "__main__":
    asyncio.run(main())
