## DNS-RouteSync-Navigator


**Основные функции:** Этот скрипт представляет собой простой DNS сервер, способный автоматически добавлять статические маршруты на роутере для указанных в фильтре доменов.
- Создано в первую очередь для роутеров Keenetic младших моделей.

**Функции:**
- Сервер принимает DNS запросы от клиентов и отправляет их на обработку публичному DNS серверу для получения IP-адресов доменов.
- Полученные DNS записи проверяются на соответствие фильтру доменов, указанному в конфигурационном файле и если DNS имя найдено в фильтре скрипт добавляет для его IP статический маршрут на роутере.
- Для взаимодействия с роутером используется Telnet-подключение.

**Зависимости:** Для работы DNS-RouteSync-Navigator необходимо наличие следующих библиотек Python:
- telnetlib3
- configparser
- dnslib

*Не забудьте установить их перед запуском:*
```
pip3 install -r requirements.txt
```

**Использование:**

Внимательно заполните конфигурационный файл config.ini, указав все параметры.

Скопируйте в domain.txt доменные имена, которые необходимо перенаправлять через отличное от основного подключения роутреа.

Установите IP машины с DNS-RouteSync-Navigator в качестве основного DNS на роутере или ПК.

Запустите скрипт. Он будет слушать DNS запросы и при совпадении доменов с фильтром, добавлять статические маршруты для перенаправления трафика к их IP через интерфейс роутера, указанный в config.ini.

#### Протестировано в Windows 11


# Скрипт написан в качестве "proof of concept"!
Автору известно большинство его проблем и недочетов, возможно, когда-нибудь они будут исправлены.

**От автора:** Скрипт является логическим продолжением DomainMapper и был задуман в качестве альтернативы OPKG пакетам на Open WRT и Keenetic OS роутерах.
Основной причиной стало обладание роутером Keenetic младшей модели - без USB, с 32 Мб ПЗУ и отсутствием возможности установки entware.
Даже при условии облегчения процесса сопоставления тысяч IP-адресов необходимых сайтов и их добавления в статические маршруты, для чего собственно и был написан DomainMapper, это занятие наскучило уже на третий день…
Главной целью была в реализации функционала OPKG пакетов дающих возможность динамически маршрутизировать трафик по разным каналам основываясь на DNS именах посещаемых сайтов.

