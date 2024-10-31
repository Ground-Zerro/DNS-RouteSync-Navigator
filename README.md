## DNS-RouteSync-Navigator
В работе: [DoT шифрование](https://github.com/Ground-Zerro/DNS-RouteSync-Navigator/issues/3#issuecomment-2302113035) для защиты DNS запросов от подмены провайдером. Доступен Alpha релиз - скачать можно по ссылке в теме.

<details>
   <summary>История изменений (нажать, чтобы открыть)</summary>

- Добавлен bash-скрипт для работы с Linux, позволяющий установить сервис как системную службу, запускать, перезапускать, останавливать и удалять службу, а также запускать в обычном интерпретаторе Python (полезно для отладки).
- Полностью реализован задуманный функционал.
- Время жизни DNS кэша уменьшено до 20 секунд.
- Кэширование IP-адресов для сокращения числа обращений (время жизни кэша — 1 час).
- Добавление маршрута больше не блокирует основную функцию DNS сервера.
- Повышена стабильность работы.

</details>

**Описание:** Скрипт на Python, предназначенный для перенаправления трафика к указанным доменам через VPN для роутеров Keenetic младших моделей без USB.

**Как работает:**
- Запускается на VPS или отдельном ПК (далее - VPS).
- Принимает DNS-запросы от хостов (устройств) и разрешает их через вышестоящий DNS-сервер.
- Проверяет поступившие DNS запросы на соответствие доменных имен пользовательскому фильтру.
- Если домен найден в фильтре, используя SSH отправляет роутеру команду на добавление статического маршрута для перенаправления трафика к этому домену (его IP-адресу) через указанное пользователем VPN-соединение.
- Фильтр учитывает субдомены. Например, если в фильтре указано "ru" то парвило сработает для всех сайтов заканчивающихся на ".ru", или если в фильтре указано "mail.ru" на роутер будут отправляться команды для добавления маршрутов ко всем адресам, заканчивающимся на ".mail.ru".

###  Использование:
1. Установите зависимости на вашем VPS:

   ```bash
   pip install -r requirements.txt
   ```
2. Создайте отдельного пользователя в роутере и разрешите ему доступ по SSH из интернета.
3. Настройте удобное вам VPN-подключение в роутере.
4. Узнайте ID VPN этого подключения (понадобится для `config.ini`):
   - Авторизуйтесь в админке роутера (например, `http://192.168.1.1`),
   - Добавьте "a" к адресу (`http://192.168.1.1/a`),
   - Введите "show interface" в командной строке,
   - Найдите ваше VPN-подключение по названию и скопируйте его ID.
5. Заполните `config.ini`, указав в нем все параметры.
6. В файл `filter.txt`, или другой текстовый файл, указанный вами в `config.ini`, внесите доменные имена, для которых нужно перенаправлять трафик.
   <details>
   <summary>(нажать, чтобы прочесть подробней)</summary>
   
   - Создайте файл, например `filter.txt`, запишите в него доменные имена - одно имя на строку. Пример:
   ```
   ab.chatgpt.com
   api.openai.com
   arena.openai.com
   ```
   - Укажите полный путь к нему в `config.ini`
   
   Важно: если записать URL вместо доменного имени (например, `ab.chatgpt.com/login` вместо `ab.chatgpt.com`) скрипт уйдет в ошибку.
   </details>

7. Запустите скрипт `main.py` на VPS.
8. Установите IP-адрес VPS с запущенным DNS-RouteSync-Navigator в качестве основного DNS-сервера на вашем роутере.
9. Если все сделанно правильно в логе RouteSync-Navigator на VPS побегут строчки о принятых DNS запросах и отправленных роутеру командах.

<details>
    <summary>Bash скрипт Linux для облегчения работы с DNS-RouteSync-Navigator (нажать, чтобы открыть)</summary>

**Что умеет:**
- Установка DNS-RouteSync-Navigator в качестве системной службы.
- Запуск, перезапуск, остановка и удаление службы.
- Запуск кода в Python (полезно для дебага).

**Использование:**  
- [Скачайте](https://raw.githubusercontent.com/Ground-Zerro/DNS-RouteSync-Navigator/main/start.sh), положите рядом с основным скриптом и запустите `start.sh`.
- Или выполните код в консоли:

    ```bash
    curl -O https://raw.githubusercontent.com/Ground-Zerro/DNS-RouteSync-Navigator/main/start.sh && chmod +x start.sh && ./start.sh
    ```
</details>

##### Протестировано на Windows 11, Ubuntu 20.04/22.04
От автора: [DNS-RouteSync-Navigator](https://github.com/Ground-Zerro/DNS-RouteSync-Navigator#dns-routesync-navigator) является продолжением проекта [DomainMapper](https://github.com/Ground-Zerro/DomainMapper) и нацелено на предоставление альтернативы OPKG пакетам, реализующим вопросы перенаправления трафика, для младших моделей роутеров Keenetic без USB.
