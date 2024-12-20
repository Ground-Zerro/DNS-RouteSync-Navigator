# Инструкция

## 1. Настройка DDNS имени для VPS от noip

### Регистрация и настройка:
1. Перейдите на сайт [No-IP Dynamic DNS](https://my.noip.com/dynamic-dns).
2. Зарегистрируйтесь.
3. В левом меню выберите:
   - **Dynamic DNS**
   - **No-IP Hostnames**
4. Нажмите кнопку **Create Hostname**.
5. Укажите DDNS имя и вставьте IP вашего сервера.

> **Важно**: Бесплатно доступен только **1 DDNS домен**.

---

## 2. Установка сертификата

### Установка certbot:
1. Обновите пакеты:
   ```bash
   sudo apt update
   ```
2. Установите certbot:
   ```bash
   sudo apt install certbot
   ```

### Получение сертификата:
1. Запустите certbot в режиме standalone:
   ```bash
   sudo certbot certonly --standalone -d example.com
   ```
   Замените `example.com` на ваш домен.
2. Следуйте инструкциям. Certbot запустит временный веб-сервер для проверки домена и получения сертификата. Убедитесь, что порты **80 (HTTP)** и/или **443 (HTTPS)** открыты и не заняты другими процессами.

### Проверка сертификата:
Сертификаты сохраняются в директории:
```bash
/etc/letsencrypt/live/example.com/
```
Замените `example.com` на ваш домен.

### Обновление сертификата:
Сертификаты Let's Encrypt действуют **90 дней**. Настройте автоматическое обновление через `cron`:

1. Откройте редактор `cron`:
   ```bash
   sudo crontab -e
   ```
2. Добавьте строку:
   ```bash
   0 0 * * * certbot renew --quiet
   ```

Это задание будет запускаться ежедневно в полночь.

---

## 3. Запуск скрипта на VPS

### Установка зависимостей:
1. Убедитесь, что у вас установлены Python 3 и pip:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
   ```
2. Установите зависимости из `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

### Подготовка конфигурации:
Убедитесь, что файл `config.ini` содержит все необходимые параметры:
- Адреса DoH серверов.
- Параметры подключения к SSH.
- Другие настройки.

### Запуск скрипта:
1. Запустите скрипт:
   ```bash
   python3 main.py
   ```
2. Если требуется, используйте `sudo`:
   ```bash
   sudo python3 main.py
   ```

### Проверка работы:
- Убедитесь, что приложение успешно запущено.
- Проверьте логи.
- Используйте инструмент `curl` для проверки DoH сервера:
   ```bash
   curl -H 'accept: application/dns-json' 'https://ИМЯ_ВАШЕГО_ДОМЕНА/dns-query?name=example.com&type=A'
   ```

---

## 4. Настройка Keenetic

### Установка компонента DoH:
1. Перейдите в **Параметры системы**.
2. Нажмите **Изменить набор компонентов**.
3. В разделе **Утилиты и Сервисы** установите компонент **Прокси-сервер DNS-over-HTTPS**.
4. Перезагрузите роутер.

### Настройка интернет-фильтров:
1. Перейдите в **Сетевые правила -> Интернет-фильтры**.
2. Нажмите **+ Добавить сервер**.
3. Укажите:
   - **Тип сервера**: DNS-over-HTTPS.
   - **URL сервера DNS**: `https://ИМЯ_ВАШЕГО_ДОМЕНА/dns-query`.

### Дополнительные настройки:
- Удалите остальные DNS серверы.
- Включите опцию **Игнорировать DNSv4 интернет-провайдера** в настройках подключения.

---

Теперь ваш скрипт и сервер готовы к работе!