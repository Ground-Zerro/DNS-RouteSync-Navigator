import asyncio
import configparser
import logging
import socket
import ssl
import time
from typing import Tuple, List, Optional, Union

import asyncssh
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE, DNSError

# Настройка логгирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Кэш для хранения IP-адресов и DNS имен
ip_cache_data = {}
dns_cache_data = {}
ip_cache_ttl = 3600  # TTL для IP-адресов в секундах
dns_cache_ttl = 20  # TTL для DNS имен в секундах

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
            if r.rtype == QTYPE.A:  # A record
                resolved_addresses.append(str(r.rdata))
                domain = str(r.rname)
                logging.info(f"Resolved {r.rname} to {r.rdata}")
    except DNSError as e:
        logging.error(f"Ошибка обработки DNS ответа: {e}")
    return domain, resolved_addresses

# Кэширование DNS имен для снижения частоты обращения к DNS серверу
def dns_cache(domain: str, resolved_addresses: List[str]) -> None:
    dns_cache_data[domain] = (time.time(), resolved_addresses)

# Проверка наличия домена в кэше
def check_dns_cache(domain: str) -> Optional[List[str]]:
    if domain in dns_cache_data:
        cache_time, cached_addresses = dns_cache_data[domain]
        if time.time() - cache_time < dns_cache_ttl:
            logging.info(f"Ответ для {domain} взят из кэша.")
            return cached_addresses
        else:
            logging.info(f"Кэш для {domain} истёк.")
            del dns_cache_data[domain]
    return None

# Расчет оставшегося времени жизни DNS записи
def get_dns_remaining_ttl(domain: str) -> Optional[int]:
    if domain in dns_cache_data:
        cache_entry_time, _ = dns_cache_data[domain]
        elapsed_time = time.time() - cache_entry_time
        remaining_ttl = int(dns_cache_ttl - elapsed_time)  # Оставшееся время жизни в секундах
        return max(0, remaining_ttl // 60)  # Оставшееся время жизни в минутах, округленное вниз
    return None

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

class SSHConnectionManager:
    def __init__(self):
        self.connection: Optional[asyncssh.SSHClientConnection] = None
        self.is_connected: bool = False

    async def connect(self, router_ip: str, ssh_port: int, login: str, password: str):
        if not self.is_connected:
            try:
                self.connection = await asyncssh.connect(
                    router_ip, port=ssh_port, username=login, password=password, known_hosts=None
                )
                self.is_connected = True
                logging.info(f"SSH подключение успешно к {router_ip}:{ssh_port}")
            except Exception as e:
                logging.error(f"Ошибка подключения SSH: {e}")
                self.is_connected = False

    async def disconnect(self):
        if self.is_connected and self.connection:
            try:
                self.connection.close()
                await self.connection.wait_closed()
                self.is_connected = False
                logging.info("SSH соединение закрыто.")
            except Exception as e:
                logging.error(f"Ошибка закрытия SSH соединения: {e}")

    async def reconnect(self, router_ip: str, ssh_port: int, login: str, password: str):
        await self.disconnect()
        await self.connect(router_ip, ssh_port, login, password)

    async def run_commands(self, commands: List[str]):
        if not self.is_connected:
            await self.connect(router_ip, router_port, login, password)
        if not self.is_connected:
            raise RuntimeError("Нет активного SSH соединения")
        try:
            results = await asyncio.gather(*(self.connection.run(command) for command in commands))
            for result in results:
                logging.info(f"Command result: {result.stdout}")
        except asyncssh.Error as e:
            logging.error(f"Ошибка при выполнении команд через SSH: {e}")
            # Попробуем переподключиться и повторить команду
            await self.reconnect(router_ip, router_port, login, password)
            try:
                results = await asyncio.gather(*(self.connection.run(command) for command in commands))
                for result in results:
                    logging.info(f"Command result: {result.stdout}")
            except asyncssh.Error as e:
                logging.error(f"Ошибка при выполнении команд через SSH после переподключения: {e}")
                raise

# Инициализация SSH менеджера
ssh_manager = SSHConnectionManager()

# Создание DNS ответа
def create_dns_response(query: DNSRecord, resolved_addresses: List[str]) -> bytes:
    dns_response = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=1, ra=1))
    dns_response.add_question(query.q)
    for address in resolved_addresses:
        dns_response.add_answer(RR(query.q.qname, QTYPE.A, rdata=A(address)))
    return dns_response.pack()

# Обработка клиента DNS-запросов
async def handle_dns_client(data: bytes, client_address: Tuple[str, int], dns_servers: List[str], request_counter: int,
                            domain_list: List[str], router_ip: str, router_port: int, login: str, password: str,
                            eth_id: str, client: Optional[Union[socket.socket, asyncio.StreamWriter]]):
    try:
        dns_query = DNSRecord.parse(data)
        domain = str(dns_query.q.qname)

        cached_addresses = check_dns_cache(domain)
        if cached_addresses:
            dns_response = create_dns_response(dns_query, cached_addresses)
            if isinstance(client, socket.socket):
                client.sendto(dns_response, client_address)
            elif isinstance(client, asyncio.StreamWriter):
                client.write(dns_response)
                await client.drain()
            return

        dns_response = await send_dns_query(data, dns_servers, request_counter)
        if dns_response:
            f_domain, resolved_addresses = process_dns_response(dns_response)
            if isinstance(client, socket.socket):
                client.sendto(dns_response, client_address)
            elif isinstance(client, asyncio.StreamWriter):
                client.write(dns_response)
                await client.drain()
            dns_cache(f_domain, resolved_addresses)  # Кэшируем ответ DNS
            if compare_dns(f_domain, domain_list):
                for address in resolved_addresses:
                    address = address.rstrip('.')
                    if not check_ip_cache(address):
                        commands = [f"ip route {address}/32 {eth_id}"]  # Добавляем маршрут
                        logging.info(f"Домен {f_domain} найден в фильтре")
                        ip_cache_data[address] = time.time()
                        try:
                            await ssh_manager.run_commands(commands)
                        except Exception as e:
                            logging.error(f"Ошибка при выполнении команд через SSH для {address}: {e}")
                            del ip_cache_data[address]
                    else:
                        remaining_ttl = get_remaining_ttl(address)
                        if remaining_ttl is not None and remaining_ttl <= 0:
                            logging.info(f"Время жизни {address} истекло, обновляем маршрут.")
                            commands = [f"ip route {address}/32 {eth_id}"]  # Обновляем маршрут
                            ip_cache_data[address] = time.time()
                            try:
                                await ssh_manager.run_commands(commands)
                            except Exception as e:
                                logging.error(f"Ошибка при выполнении команд через SSH для {address}: {e}")
                                del ip_cache_data[address]
                        else:
                            if remaining_ttl is not None:
                                logging.info(f"{address} был добавлен ранее, оставшееся время жизни: {remaining_ttl} минут")

    except Exception as e:
        logging.error(f"Ошибка обработки DNS-запроса: {e}")

# Обработка клиента DNS-over-TLS запросов
async def handle_dot_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                            dns_servers: List[str], request_counter: int, domain_list: List[str],
                            router_ip: str, router_port: int, login: str, password: str, eth_id: str):
    try:
        data = await reader.read(1024)
        client_address = writer.get_extra_info('peername')
        await handle_dns_client(data, client_address, dns_servers, request_counter, domain_list,
                                router_ip, router_port, login, password, eth_id, writer)
    except Exception as e:
        logging.error(f"Ошибка обработки DNS-over-TLS запроса: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

# Запуск обычного DNS сервера
async def start_dns_server(server_ip: str, dns_servers: List[str], domain_list: List[str], router_ip: str, router_port: int,
                           login: str, password: str, eth_id: str):
    logging.info("Запуск обычного DNS сервера...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.settimeout(10)
    loop = asyncio.get_event_loop()
    server_socket.bind((server_ip, 53))  # Обычный DNS сервер на порту 53
    logging.info('Обычный DNS сервер запущен на порту 53')

    async def recvfrom_loop() -> None:
        request_counter = 0
        while True:
            try:
                data, client_address = await loop.run_in_executor(None, server_socket.recvfrom, 1024)
                asyncio.create_task(handle_dns_client(data, client_address, dns_servers, request_counter, domain_list,
                                                      router_ip, router_port, login, password, eth_id, server_socket))
                request_counter += 1
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Ошибка в основной петле DNS: {e}")

    try:
        await recvfrom_loop()
    finally:
        server_socket.close()


# Запуск DNS-over-TLS сервера
async def start_dot_server(host: str, port: int, dns_servers: List[str], request_counter: int, domain_list: List[str],
                           router_ip: str, router_port: int, login: str, password: str, eth_id: str):
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile='fullchain.pem', keyfile='privkey.pem')

    server = await asyncio.start_server(
        lambda r, w: handle_dot_client(r, w, dns_servers, request_counter, domain_list,
                                       router_ip, router_port, login, password, eth_id),
        host, port, ssl=ssl_context
    )
    logging.info(f'DNS-over-TLS сервер запущен на {host}:{port}')
    async with server:
        await server.serve_forever()

# Основная функция
async def main():
    logging.info("Чтение конфигурационного файла...")
    config = read_config('config.ini')
    if not config:
        return

    logging.info("Загрузка доменных имен...")
    dns_servers = [config.get('public_dns_1'), config.get('public_dns_2')]
    global router_ip, router_port, login, password, eth_id
    router_ip = config.get('router_ip')
    router_port = int(config.get('router_port'))
    login = config.get('login')
    password = config.get('password')
    eth_id = config.get('eth_id')
    domain_file = config.get('domain_file')
    server_ip = config.get('server_ip')
    domain_list = load_domain_list(domain_file)

    logging.info("Подключение к SSH...")
    await ssh_manager.connect(router_ip, router_port, login, password)

    mode = config.get('mode', 'mix')
    if mode in ['mix', 'main']:
        asyncio.create_task(start_dns_server(server_ip, dns_servers, domain_list, router_ip, router_port, login, password, eth_id))
    if mode in ['mix', 'dot']:
        asyncio.create_task(start_dot_server(server_ip, 853, dns_servers, 0, domain_list, router_ip, router_port, login, password, eth_id))

    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())
