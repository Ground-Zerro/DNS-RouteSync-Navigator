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


# Чтение конфигурационного файла
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


# Отправка DNS запроса к публичному DNS серверу
async def send_dns_query(data: bytes, dns_servers: List[str], request_counter: int) -> Optional[bytes]:
    loop = asyncio.get_event_loop()
    current_dns = dns_servers[request_counter % len(dns_servers)]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            client_socket.settimeout(2)
            await loop.run_in_executor(None, client_socket.sendto, data, (current_dns, 53))
            response, _ = await loop.run_in_executor(None, client_socket.recvfrom, 1024)
            return response
    except socket.timeout:
        logging.warning(f"Тайм-аут при отправке DNS запроса к {current_dns}")
        return None
    except Exception as e:
        logging.error(f"Ошибка отправки DNS запроса: {e}")
        return None


# Обработка ответа от DNS сервера
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


# Кэширование DNS имен для снижения частоты обращения к DNS серверу
def dns_cache(domain: str, resolved_addresses: List[str]) -> List[str]:
    if domain in dns_cache_data:
        return dns_cache_data[domain]
    dns_cache_data[domain] = resolved_addresses
    return resolved_addresses


# Поиск DNS имени в фильтре
def compare_dns(f_domain: str, domain_list: List[str]) -> bool:
    name_parts = f_domain.rstrip('.').split('.')
    for filter_domain in domain_list:
        filter_domain_parts = filter_domain.split('.')
        if len(name_parts) < len(filter_domain_parts):
            continue
        match = all(name_parts[i] == filter_domain_parts[i] for i in range(-1, -len(filter_domain_parts) - 1, -1))
        if match:
            return True
    return False


# Класс для пула SSH соединений
class SSHConnectionPool:
    def __init__(self, max_size: int):
        self.pool = asyncio.Queue(max_size)
        self.max_size = max_size
        self.size = 0

    async def get_connection(self, router_ip: str, ssh_port: int, login: str,
                             password: str) -> asyncssh.SSHClientConnection:
        if self.pool.empty() and self.size < self.max_size:
            connection = await asyncssh.connect(
                router_ip, port=ssh_port, username=login, password=password, known_hosts=None, keepalive_interval=30
            )
            self.size += 1
            return connection
        else:
            return await self.pool.get()

    async def release_connection(self, connection: asyncssh.SSHClientConnection):
        await self.pool.put(connection)

    async def close_all(self):
        while not self.pool.empty():
            connection = await self.pool.get()
            connection.close()
            self.size -= 1


# Инициализация пула SSH соединений
ssh_pool = SSHConnectionPool(max_size=5)


# Отправка команд через SSH
async def send_commands_via_ssh(router_ip: str, ssh_port: int, login: str, password: str, commands: List[str]) -> None:
    connection = None
    try:
        connection = await ssh_pool.get_connection(router_ip, ssh_port, login, password)
        results = await asyncio.gather(*(connection.run(command) for command in commands))
        for result in results:
            logging.info(f"Command result: {result.stdout}")
    except asyncssh.Error as e:
        logging.error(f"Ошибка при выполнении команд через SSH: {e}")
        for command in commands:
            ip_address = command.split()[2]
            if ip_cache(ip_address):
                del ip_cache_data[ip_address]
        raise
    except asyncio.TimeoutError:
        logging.error(f"Не удалось соединиться с {router_ip}")
        for command in commands:
            ip_address = command.split()[2]
            if ip_cache(ip_address):
                del ip_cache_data[ip_address]
        raise
    finally:
        if connection:
            await ssh_pool.release_connection(connection)


# Кэширование IP-адресов
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

    async def handle_client(data: bytes, client_address: Tuple[str, int], dns_servers: List[str], request_counter: int,
                            domain_list: List[str]) -> None:
        try:
            dns_query = DNSRecord.parse(data)
            domain = str(dns_query.q.qname)

            if domain in dns_cache_data:
                cached_response = dns_cache_data[domain]
                server_socket.sendto(cached_response, client_address)
                logging.info(f"Ответ для {domain} взят из кэша.")
                return
        except DNSError as e:
            logging.error(f"Ошибка парсинга DNS запроса: {e}")
            return

        dns_response = await send_dns_query(data, dns_servers, request_counter)
        if dns_response:
            f_domain, resolved_addresses = process_dns_response(dns_response)
            server_socket.sendto(dns_response, client_address)
            dns_cache_data[f_domain] = dns_response  # Кэшируем ответ DNS
            match = compare_dns(f_domain, domain_list)
            if match:
                for address in resolved_addresses:
                    if not ip_cache(address.rstrip('.')):
                        commands = [f"ip route {address.rstrip('.')}/32 {eth_id}" for address in resolved_addresses]
                        logging.info(f"Домен {f_domain} найден в фильтре")
                        ip_cache_data[address.rstrip('.')] = time.time()
                        try:
                            await asyncio.wait_for(
                                send_commands_via_ssh(router_ip, router_port, login, password, commands), timeout=5
                            )
                        except (asyncssh.Error, ConnectionResetError) as e:
                            logging.error(f"Ошибка при выполнении команд через SSH для {address}: {e}")
                            del ip_cache_data[address.rstrip('.')]
                        except asyncio.TimeoutError:
                            logging.error(f"Не удалось соединиться с {router_ip}:{router_port}")
                            del ip_cache_data[address.rstrip('.')]
                        except OSError as e:
                            logging.error(f"Ошибка подключения: {e}")
                            del ip_cache_data[address.rstrip('.')]
                    else:
                        cache_entry_time = ip_cache_data[address.rstrip('.')]
                        if time.time() - cache_entry_time >= 21600:  # TTL check for 6 hours
                            logging.info(f"Время жизни {address.rstrip('.')} истекло, обновляем маршрут.")
                            commands = [f"ip route {address.rstrip('.')}/32 {eth_id}" for address in resolved_addresses]
                            ip_cache_data[address.rstrip('.')] = time.time()
                            try:
                                await asyncio.wait_for(
                                    send_commands_via_ssh(router_ip, router_port, login, password, commands), timeout=5
                                )
                            except (asyncssh.Error, ConnectionResetError) as e:
                                logging.error(f"Ошибка при выполнении команд через SSH для {address}: {e}")
                                del ip_cache_data[address.rstrip('.')]
                            except asyncio.TimeoutError:
                                logging.error(f"Не удалось соединиться с {router_ip}:{router_port}")
                                del ip_cache_data[address.rstrip('.')]
                            except OSError as e:
                                logging.error(f"Ошибка подключения: {e}")
                                del ip_cache_data[address.rstrip('.')]
                        else:
                            remaining_ttl = int((21600 - (time.time() - cache_entry_time)) / 60)
                            logging.info(f"{address.rstrip('.')} был добавлен ранее, оставшееся время жизни:"
                                         f" {remaining_ttl} минут")

    async def recvfrom_loop(dns_servers: List[str], domain_list: List[str]) -> None:
        request_counter = 0
        while True:
            try:
                data, client_address = await loop.run_in_executor(None, server_socket.recvfrom, 1024)
                asyncio.create_task(handle_client(data, client_address, dns_servers, request_counter, domain_list))
                request_counter += 1
            except socket.timeout:
                continue
            except Exception as E:
                logging.error(f"Ошибка в основной петле: {E}")

    try:
        await recvfrom_loop(dns_servers, domain_list)
    finally:
        server_socket.close()
        await ssh_pool.close_all()

if __name__ == "__main__":
    asyncio.run(main())
