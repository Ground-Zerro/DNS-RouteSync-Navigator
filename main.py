import asyncio
import configparser
import logging
import socket
import time
from typing import Tuple, List, Optional

import asyncssh
from cachetools import TTLCache
from dnslib import DNSRecord, DNSError


# Настройка логгирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Кэш для хранения IP-адресов и DNS имен
ip_cache_data = TTLCache(maxsize=1000, ttl=21600)  # Кэш IP адресов с TTL 6 часов
dns_cache_data = TTLCache(maxsize=1000, ttl=60)    # Кэш DNS имен с TTL 1 минута


# Глобальная переменная для хранения доменных имен
domain_list = []


# Переменные для работы с двумя DNS серверами
dns_servers = []
request_counter = 0


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


# Загрузка доменных имен в память
def load_domain_list(domain_file: str) -> List[str]:
    try:
        with open(domain_file, 'r', encoding='utf-8-sig') as file:
            domains = [line.strip() for line in file if line.strip()]
            logging.info(f"Доменные имена загружены из файла {domain_file}.")
            return domains
    except Exception as e:
        logging.error(f"Ошибка загрузки доменных имен из файла {domain_file}: {e}")
        return []


# Функция для отправки DNS запросов к публичному DNS серверу
async def send_dns_query(data: bytes) -> Optional[bytes]:
    global request_counter
    loop = asyncio.get_event_loop()
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5)  # Устанавливаем тайм-аут на 5 секунд

    # Определяем текущий DNS сервер
    current_dns = dns_servers[request_counter % len(dns_servers)]
    request_counter += 1

    try:
        await loop.run_in_executor(None, client_socket.sendto, data, (current_dns, 53))
        response, _ = await loop.run_in_executor(None, client_socket.recvfrom, 1024)
        return response
    except socket.timeout:
        logging.warning(f"Тайм-аут при отправке DNS запроса к {current_dns}")
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
def compare_dns(f_domain: str) -> bool:
    try:
        name_parts = f_domain.rstrip('.').split('.')
        for filter_domain in domain_list:
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
                logging.error(result.stderr)
    except asyncssh.Error as e:
        logging.error(f"Ошибка при выполнении команд через SSH: {e}")


# Функция кэширования IP-адресов для снижения частоты обращения к роутеру
def ip_cache(address: str) -> bool:
    return address in ip_cache_data


# Основная функция
async def main() -> None:
    global domain_list
    global dns_servers
    
    config_data = read_config('config.ini')
    if not config_data:
        return

    try:
        router_ip = config_data['router_ip']
        router_port = int(config_data['router_port'])
        login = config_data['login']
        password = config_data['password']
        eth_id = config_data['eth_id']
        domain_file = config_data['domain_file']
        public_dns_1 = config_data['public_dns_1']
        public_dns_2 = config_data['public_dns_2']
        server_ip = config_data['server_ip']
        server_port = int(config_data['server_port'])
        
        # Загрузка доменных имен в память
        domain_list = load_domain_list(domain_file)
        
        # Инициализация списка DNS серверов
        dns_servers = [public_dns_1, public_dns_2]
        
    except KeyError as e:
        logging.error(f"Ошибка чтения параметров конфигурации: отсутствует ключ {e}")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.settimeout(10)  # Тайм-аут для сервера
    loop = asyncio.get_event_loop()
    server_socket.bind((server_ip, server_port))
    logging.info(f'DNS сервер запущен {server_ip}:{server_port}')

    async def handle_client(data: bytes, client_address: Tuple[str, int]) -> None:
        dns_response = await send_dns_query(data)
        if dns_response:
            f_domain, resolved_addresses = process_dns_response(dns_response)
            server_socket.sendto(dns_response, client_address)
            match = compare_dns(f_domain)
            if match:
                for address in resolved_addresses:
                    if not ip_cache(address.rstrip('.')):
                        commands = [f"ip route {address.rstrip('.')}/32 {eth_id}" for address in resolved_addresses]
                        logging.info(f"домен {f_domain} найден в фильтре - добавляем маршрут для него")
                        ip_cache_data[address.rstrip('.')] = time.time()
                        try:
                            await send_commands_via_ssh(router_ip, router_port, login, password, commands)
                        except (asyncssh.Error, ConnectionResetError) as e:
                            logging.error(f"Ошибка при выполнении команд через SSH для {address}: {e}")
                    else:
                        remaining_ttl = int((ip_cache_data[address.rstrip('.')] + 10800 - time.time()) / 60)
                        logging.info(f"{address.rstrip('.')} кэширован, оставшееся время жизни: {remaining_ttl} минут")

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
