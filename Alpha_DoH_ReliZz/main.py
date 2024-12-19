import asyncio
import configparser
import logging
import ssl
import time
from typing import List, Optional, Tuple

import asyncssh
import dns.exception
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import httpx
from aiohttp import web

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

# Отправка DNS запроса через DNS-over-HTTPS (DoH)
async def send_doh_query(data: bytes, dns_servers: List[str], request_counter: int) -> Optional[bytes]:
    current_dns = dns_servers[request_counter % len(dns_servers)]
    url = f"https://{current_dns}/dns-query"

    headers = {
        'Content-Type': 'application/dns-message',
    }

    logging.debug(f"Отправка DoH запроса к {current_dns} с данными длиной {len(data)}")
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            response = await client.post(url, content=data, headers=headers)
            logging.debug(f"Получен ответ от DoH сервера {current_dns} с кодом состояния {response.status_code}")
            if response.status_code == 200:
                return response.content
            else:
                logging.warning(f"Ошибка DoH запроса к {current_dns}: {response.status_code}")
                return None
    except httpx.RequestError as e:
        logging.error(f"Ошибка отправки DoH запроса: {e}")
        return None

# Обработка ответа от DNS сервера
def process_dns_response(dns_response: bytes) -> Tuple[str, List[str]]:
    resolved_addresses = []
    domain = ""
    try:
        response_message = dns.message.from_wire(dns_response)
        logging.debug(f"Обработка DNS ответа, количество ответов: {len(response_message.answer)}")
        if response_message.answer:
            for answer in response_message.answer:
                for item in answer:
                    if item.rdtype == dns.rdatatype.A:
                        resolved_addresses.append(item.address)
                        domain = str(response_message.question[0].name)
                        logging.info(f"Resolved {domain} to {item.address}")
    except dns.exception.DNSException as e:
        logging.error(f"Ошибка обработки DNS ответа: {e}")
        logging.error(f"Полученные данные DNS ответа: {dns_response}")
    return domain, resolved_addresses

# Создание DNS ответа
def create_dns_response(query: dns.message.Message, resolved_addresses: List[str]) -> bytes:
    response_message = dns.message.make_response(query)
    response_message.set_rcode(dns.rcode.NOERROR)
    for address in resolved_addresses:
        rrset = dns.rrset.from_text(
            query.question[0].name,
            300,  # TTL
            dns.rdataclass.IN,
            dns.rdatatype.A,
            address
        )
        response_message.answer.append(rrset)
    logging.debug(f"Создан DNS ответ с {len(resolved_addresses)} адресами")
    return response_message.to_wire()

# Кэширование DNS имен
def dns_cache(domain: str, resolved_addresses: List[str]) -> None:
    dns_cache_data[domain] = (time.time(), resolved_addresses)
    logging.debug(f"Кэширование DNS ответа для {domain}")

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

# Проверка наличия IP-адреса в кэше
def check_ip_cache(address: str) -> bool:
    if address in ip_cache_data:
        cache_entry_time = ip_cache_data[address]
        if time.time() - cache_entry_time >= ip_cache_ttl:
            logging.debug(f"Кэш для IP адреса {address} истёк.")
            del ip_cache_data[address]
            return False
        logging.debug(f"IP адрес {address} найден в кэше.")
        return True
    return False

# Расчет оставшегося времени жизни IP-адреса
def get_remaining_ttl(address: str) -> Optional[int]:
    if address in ip_cache_data:
        cache_entry_time = ip_cache_data[address]
        elapsed_time = time.time() - cache_entry_time
        remaining_ttl = int(ip_cache_ttl - elapsed_time)
        return max(0, remaining_ttl // 60)  # TTL в минутах
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
            raise RuntimeError("Нет активного SSH соединения")
        try:
            results = await asyncio.gather(*(self.connection.run(command) for command in commands))
            for result in results:
                logging.info(f"Результат выполнения команды: {result.stdout}")
        except asyncssh.Error as e:
            logging.error(f"Ошибка при выполнении команд через SSH: {e}")
            await self.reconnect(router_ip, router_port, login, password)
            results = await asyncio.gather(*(self.connection.run(command) for command in commands))
            for result in results:
                logging.info(f"Результат выполнения команды после переподключения: {result.stdout}")

# Инициализация SSH менеджера
ssh_manager = SSHConnectionManager()

async def handle_doh_request(request: web.Request) -> web.Response:
    global request_counter
    try:
        data = await request.read()
        logging.info(f"Получены данные DNS запроса длиной {len(data)}")
        dns_query = dns.message.from_wire(data)
        domain = str(dns_query.question[0].name)
        logging.debug(f"Получен DNS запрос для домена {domain}")

        # Проверка кэша
        cached_addresses = check_dns_cache(domain)
        if cached_addresses:
            logging.info(f"Ответ для домена {domain} найден в кэше.")
            dns_response = create_dns_response(dns_query, cached_addresses)
            return web.Response(body=dns_response, content_type='application/dns-message')

        # Отправка запроса через DoH
        dns_response = await send_doh_query(data, dns_servers, request_counter)
        request_counter += 1  # Увеличение счетчика запросов
        if dns_response:
            f_domain, resolved_addresses = process_dns_response(dns_response)
            dns_cache(f_domain, resolved_addresses)  # Кэширование ответа
            logging.debug(f"Обработан DNS ответ для {f_domain}, найдено {len(resolved_addresses)} адресов")

            if compare_dns(f_domain, domain_list):
                for address in resolved_addresses:
                    if not check_ip_cache(address):
                        commands = [f"ip route {address}/32 {eth_id}"]  # Добавление маршрута
                        ip_cache_data[address] = time.time()
                        logging.info(f"Добавление маршрута для IP адреса {address}")
                        try:
                            await ssh_manager.run_commands(commands)
                        except Exception as e:
                            logging.error(f"Ошибка при выполнении команд через SSH для {address}: {e}")
                            del ip_cache_data[address]
            dns_response = create_dns_response(dns_query, resolved_addresses)
            return web.Response(body=dns_response, content_type='application/dns-message')
        else:
            logging.error("Ошибка получения ответа от DNS сервера")
            return web.Response(text="Ошибка получения ответа от DNS сервера", status=502)

    except Exception as e:
        logging.error(f"Ошибка обработки DNS-запроса: {e}")
        return web.Response(text=f"Ошибка: {e}", status=500)

# Основная функция
async def main():
    logging.info("Чтение конфигурационного файла...")
    config = read_config('config.ini')
    if not config:
        return

    logging.info("Загрузка доменных имен...")
    global dns_servers, router_ip, router_port, login, password, eth_id, domain_list, request_counter
    dns_servers = [config.get('public_doh_1'), config.get('public_doh_2')]
    router_ip = config.get('router_ip')
    router_port = int(config.get('router_port'))
    login = config.get('login')
    password = config.get('password')
    eth_id = config.get('eth_id')
    domain_file = config.get('domain_file')
    domain_list = load_domain_list(domain_file)
    request_counter = 0  # Инициализация счетчика запросов

    logging.info("Подключение к SSH...")
    await ssh_manager.connect(router_ip, router_port, login, password)

    # Настройка SSL контекста
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=config.get('ssl_cert_file'), keyfile=config.get('ssl_key_file'))

    app = web.Application()  # Создаем экземпляр приложения
    app.router.add_post('/dns-query', handle_doh_request)

    logging.info("Запуск DoH сервера...")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host='0.0.0.0', port=443, ssl_context=ssl_context)
    await site.start()

    try:
        while True:
            await asyncio.sleep(3600)  # Обновляем каждую минуту

    except asyncio.CancelledError:
        pass
    finally:
        logging.info("Остановка сервера...")
        await runner.cleanup()
        await ssh_manager.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
