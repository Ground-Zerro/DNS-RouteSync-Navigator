## DNS-RouteSync-Navigator
В работе: [DoT шифрование](https://github.com/Ground-Zerro/DNS-RouteSync-Navigator/issues/3#issuecomment-2302113035) для защиты DNS запросов от подмены провайдером. 
<details>
   <summary>История изменений (нажать, чтобы открыть)</summary>

- Повышена стабильность работы.
- Добавление маршрута больше не блокирует основную функцию DNS сервера.
- Кэширование IP-адресов для сокращения числа обращений (время жизни кэша — 1 час).
- Время жизни DNS кэша уменьшено до 20 секунд.
- Полностью реализован задуманный функционал.
- Добавлен bash-скрипт для работы с Linux, позволяющий установить сервис как системную службу, запускать, перезапускать, останавливать и удалять службу, а также запускать в обычном интерпретаторе Python (полезно для отладки).
</details>

**Описание:** Скрипт на Python, предназначенный для перенаправления трафика к указанным доменам через VPN для роутеров Keenetic младших моделей без USB.

**Функции:**
- Принимает DNS-запросы от клиентов и разрешает их с использованием вышестоящего DNS-сервера.
- Проверяет доменные имена по пользовательскому фильтру.
- При совпадении добавляет статический маршрут на роутере через SSH, перенаправляя трафик к IP-адресу через указанное VPN-соединение.
- Фильтрация доменов может быть по полному или частичному совпадению с вышестоящим доменом (например, "ru" — для всех доменов RU зоны или "mail.ru" — для всех, заканчивающихся на ".mail.ru").

###  Использование:
1. Установите зависимости:

   ```bash
   pip install -r requirements.txt
   ```
2. Создайте пользователя в роутере и разрешите доступ по SSH.
3. Настройте VPN-подключение в роутере.
4. Узнайте ID VPN подключения:
   - Авторизуйтесь в админке роутера (например, `http://192.168.1.1`),
   - Добавьте "a" к адресу (`http://192.168.1.1/a`),
   - Введите "show interface" в командной строке,
   - Найдите ваше VPN-подключение по названию и скопируйте его ID.
5. Заполните `config.ini`, указав все параметры.
6. В текстовый файл внесите доменные имена, для которых нужно перенаправление трафика.
7. Установите IP машины с запущенным DNS-RouteSync-Navigator в качестве основного DNS-сервера на роутере или ПК.

<details>
    <summary>Скрипт под Linux для облегчения работы с DNS-RouteSync-Navigator под Linux: (нажать, чтобы открыть)</summary>

**Что умеет:**
- Установка DNS-RouteSync-Navigator в качестве системной службы.
- Запуск, перезапуск, остановка и удаление службы.
- Запуск кода через Python интерпретатор (полезно для дебага).

**Использование:**  
- [Скачайте](https://raw.githubusercontent.com/Ground-Zerro/DNS-RouteSync-Navigator/main/start.sh), положите рядом с основным скриптом и запустите `start.sh`.
- Или выполните код в консоли:

    ```bash
    curl -O https://raw.githubusercontent.com/Ground-Zerro/DNS-RouteSync-Navigator/main/start.sh && chmod +x start.sh && ./start.sh
    ```
</details>

##### Протестировано на Windows 11, Ubuntu 20.04/22.04
От автора: [DNS-RouteSync-Navigator](https://github.com/Ground-Zerro/DNS-RouteSync-Navigator#dns-routesync-navigator) является продолжением проекта [DomainMapper](https://github.com/Ground-Zerro/DomainMapper) и нацелено на предоставление альтернативы OPKG пакетам, реализующим вопросы перенаправления трафика, для младших моделей роутеров Keenetic.