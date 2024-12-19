import asyncio
import configparser
import logging
import socket
import time
from typing import Tuple, List, Optional

import asyncssh
from dnslib import DNSRecord, DNSError

# Настройка логгирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Кэш для хранения IP-адресов и DNS имен
ip_cache_data = {}  # Словарь для хранения времени добавления IP-адресов
dns_cache_data = {}  # Словарь для хранения данных DNS и времени их добавления
ip_cache_ttl = 3600  # TTL для IP-адресов в секундах
dns_cache_ttl = 20   # TTL для DNS имен в секундах

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

# Проверка наличия DNS записи в кэше и его времени жизни
def check_dns_cache(domain: str) -> Optional[bytes]:
    if domain in dns_cache_data:
        cache_entry_time, response = dns_cache_data[domain]
        if time.time() - cache_entry_time >= dns_cache_ttl:
            # TTL истек
            del dns_cache_data[domain]
            return None
        return response
    return None

# Расчет оставшегося времени жизни DNS записи
def get_dns_remaining_ttl(domain: str) -> Optional[int]:
    if domain in dns_cache_data:
        cache_entry_time, _ = dns_cache_data[domain]
        elapsed_time = time.time() - cache_entry_time
        remaining_ttl = int(dns_cache_ttl - elapsed_time)  # Оставшееся время жизни в секундах
        return max(0, remaining_ttl // 60)  # Оставшееся время жизни в минутах, округленное вниз
    return None

# Кэширование DNS имен для снижения частоты обращения к DNS серверу
def dns_cache(domain: str, resolved_addresses: List[str]) -> List[str]:
    dns_response = DNSRecord.question(domain).pack()  # Пример формирования DNS запроса для кэширования
    dns_cache_data[domain] = (time.time(), dns_response)
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

# Проверка наличия IP-адреса в кэше и его времени жизни
def check_ip_cache(address: str) -> bool:
    if address in ip_cache_data:
        cache_entry_time = ip_cache_data[address]
        if time.time() - cache_entry_time >= ip_cache_ttl:
            # TTL истек
            del ip_cache_data[address]
            return False
        return True
    return False

# Расчет оставшегося времени жизни IP-адреса
def get_remaining_ttl(address: str) -> Optional[int]:
    if address in ip_cache_data:
        cache_entry_time = ip_cache_data[address]
        elapsed_time = time.time() - cache_entry_time
        remaining_ttl = int(ip_cache_ttl - elapsed_time)  # Оставшееся время жизни в секундах
        return max(0, remaining_ttl // 60)  # Оставшееся время жизни в минутах, округленное вниз
    return None

# Класс для работы с одним SSH соединением
# Класс для работы с одним SSH соединением
# Класс для работы с одним SSH соединением
class SSHConnectionManager:
    def __init__(self):
        self.connection: Optional[asyncssh.SSHClientConnection] = None
        self.keepalive_interval = 600  # 10 минут

    async def connect(self, router_ip: str, ssh_port: int, login: str, password: str):
        if not self.connection:
            try:
                self.connection = await asyncssh.connect(
                    router_ip, port=ssh_port, username=login, password=password, known_hosts=None
                )
                asyncio.create_task(self.keepalive())
            except asyncssh.PermissionDenied as e:
                logging.error(f"Ошибка подключения по SSH к {router_ip}:{ssh_port} - Доступ запрещен: {e}")
                # Не останавливаем выполнение программы, просто не подключаемся
            except asyncssh.Error as e:
                logging.error(f"Ошибка подключения по SSH к {router_ip}:{ssh_port} - {e}")
                # Не останавливаем выполнение программы, просто не подключаемся
            except Exception as e:
                logging.error(f"Неизвестная ошибка при подключении по SSH к {router_ip}:{ssh_port} - {e}")
                # Не останавливаем выполнение программы, просто не подключаемся

    async def keepalive(self):
        while self.connection:
            try:
                await self.connection.run("echo keepalive")
                await asyncio.sleep(self.keepalive_interval)
            except Exception as e:
                logging.error(f"Ошибка при поддержке SSH соединения: {e}")
                break


    async def run_commands(self, commands: List[str]):
        if not self.connection:
            raise RuntimeError("Нет активного SSH соединения")
        try:
            results = await asyncio.gather(*(self.connection.run(command) for command in commands))
            for result in results:
                logging.info(f"Command result: {result.stdout}")
        except asyncssh.Error as e:
            logging.error(f"Ошибка при выполнении команд через SSH: {e}")
            raise


# Инициализация SSH менеджера
ssh_manager = SSHConnectionManager()

# Основная функция обработки клиента
async def handle_client(data: bytes, client_address: Tuple[str, int], dns_servers: List[str], request_counter: int,
                        domain_list: List[str], router_ip: str, router_port: int, login: str, password: str,
                        eth_id: str, server_socket: socket.socket):
    try:
        dns_query = DNSRecord.parse(data)
        domain = str(dns_query.q.qname)

        cached_response = check_dns_cache(domain)
        if cached_response:
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
        dns_cache(f_domain, resolved_addresses)  # Кэшируем ответ DNS
        match = compare_dns(f_domain, domain_list)
        if match:
            for address in resolved_addresses:
                if not check_ip_cache(address.rstrip('.')):
                    commands = [f"ip route {address.rstrip('.')}/32 {eth_id}" for address in resolved_addresses]
                    logging.info(f"Домен {f_domain} найден в фильтре")
                    ip_cache_data[address.rstrip('.')] = time.time()
                    try:
                        await ssh_manager.run_commands(commands)
                    except Exception as e:
                        logging.error(f"Ошибка при выполнении команд через SSH для {address}: {e}")
                        del ip_cache_data[address.rstrip('.')]
                else:
                    remaining_ttl = get_remaining_ttl(address.rstrip('.'))
                    if remaining_ttl is not None and remaining_ttl <= 0:
                        logging.info(f"Время жизни {address.rstrip('.')} истекло, обновляем маршрут.")
                        commands = [f"ip route {address.rstrip('.')}/32 {eth_id}" for address in resolved_addresses]
                        ip_cache_data[address.rstrip('.')] = time.time()
                        try:
                            await ssh_manager.run_commands(commands)
                        except Exception as e:
                            logging.error(f"Ошибка при выполнении команд через SSH для {address}: {e}")
                            del ip_cache_data[address.rstrip('.')]
                    else:
                        if remaining_ttl is not None:
                            logging.info(f"{address.rstrip('.')} был добавлен ранее, оставшееся время жизни: {remaining_ttl} минут")

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

        # Создание и поддержка SSH соединения
        await ssh_manager.connect(router_ip, router_port, login, password)

    except KeyError as e:
        logging.error(f"Ошибка чтения параметров конфигурации: отсутствует ключ {e}")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.settimeout(10)  # Тайм-аут для сервера
    loop = asyncio.get_event_loop()
    server_socket.bind((server_ip, server_port))
    logging.info(f'DNS сервер запущен {server_ip}:{server_port}')

    async def recvfrom_loop(dns_servers: List[str], domain_list: List[str]) -> None:
        request_counter = 0
        while True:
            try:
                data, client_address = await loop.run_in_executor(None, server_socket.recvfrom, 1024)
                asyncio.create_task(handle_client(data, client_address, dns_servers, request_counter, domain_list,
                                                  router_ip, router_port, login, password, eth_id, server_socket))
                request_counter += 1
            except socket.timeout:
                continue
            except Exception as E:
                logging.error(f"Ошибка в основной петле: {E}")

    try:
        await recvfrom_loop(dns_servers, domain_list)
    finally:
        server_socket.close()

if __name__ == "__main__":
    asyncio.run(main())
