подготовка 
```bash
sudo mkdir -p /etc/ldns/
sudo wget -O /etc/ldns/root.hints https://www.internic.net/domain/named.root
sudo chmod 644 /etc/ldns/root.hints
```
-----

### Шаг 1: Клонирование репозитория

Сначала склонируйте репозиторий с исходным кодом на ваш сервер.

```bash
git clone https://github.com/ASTRACAT2022/DNS-C-.git
```

Эта команда создаст на вашем сервере директорию `DNS-C-` со всеми файлами проекта.

-----

### Шаг 2: Установка зависимостей

Перейдите в директорию проекта и установите все необходимые библиотеки.

```bash
cd DNS-C-
sudo apt update
sudo apt install build-essential git libldns-dev -y
```

  * `build-essential`: Содержит компилятор `g++` и другие инструменты для сборки.
  * `git`: Убедитесь, что `git` установлен для работы с репозиторием.
  * `libldns-dev`: Это заголовочные файлы и библиотеки для `ldns`, которые нужны для компиляции.

-----

### Шаг 3: Компиляция

Скомпилируйте исходный код в исполняемый файл.

```bash
g++ -o dns_resolver app.cpp -I/usr/include -L/usr/lib/x86_64-linux-gnu -lldns -pthread
```

  * `-o dns_resolver`: Название исполняемого файла.
  * `app.cpp`: Имя файла с исходным кодом.
  * `-I/usr/include` и `-L/usr/lib/...`: Указывают компилятору, где искать заголовочные файлы и библиотеки `ldns`.
  * `-lldns`: Подключает библиотеку `ldns`.
  * `-pthread`: Подключает поддержку многопоточности.

-----

### Шаг 4: Тестирование

Перед развёртыванием через `systemd`, убедитесь, что приложение работает локально.

```bash
./dns_resolver
```

В другом терминале отправьте тестовый DNS-запрос:

```bash
dig @127.0.0.1 -p 5313 google.com
```

Если вы получили ответ, всё работает корректно. Нажмите `Ctrl+C`, чтобы остановить приложение.

-----

### Шаг 5: Настройка `systemd`

Чтобы сервис запускался автоматически, настройте `systemd`.

1.  **Создайте системную директорию** для вашего приложения и скопируйте исполняемый файл:
    ```bash
    sudo mkdir -p /opt/dns-resolver
    sudo cp dns_resolver /opt/dns-resolver/
    ```
2.  **Создайте юнит-файл** для `systemd`:
    ```bash
    sudo nano /etc/systemd/system/dns-resolver.service
    ```
3.  **Вставьте следующий код** в файл, сохраните и закройте его:
    ```ini
    [Unit]
    Description=The ASTRAnet DNS Resolver Service
    After=network.target

    [Service]
    Type=simple
    ExecStart=/opt/dns-resolver/dns_resolver
    Restart=always
    User=root
    Group=root
    WorkingDirectory=/opt/dns-resolver/

    [Install]
    WantedBy=multi-user.target
    ```
4.  **Перезагрузите `systemd`** и запустите сервис:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl start dns-resolver
    sudo systemctl enable dns-resolver
    ```

После этого ваш DNS-резолвер будет автоматически запускаться при старте системы и будет готов к работе.
