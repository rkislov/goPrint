# Установка GoPrint на Linux

Пакеты GoPrint v0.2.0-beta.7 доступны на [странице выпуска](https://github.com/rkislov/goPrint/releases/tag/v0.2.0-beta.7). Сверьте SHA-256 выбранного файла с SHA256SUMS.

- ALT Linux 10 и 11, x86_64 и aarch64: отдельные RPM для p10 и p11. См. [инструкцию ALT](ALT-LINUX.md).
- Ubuntu 24.04 LTS, amd64 и arm64: goprint-v0.2.0-beta.7-ubuntu24.04-ARCH.deb.
- Astra Linux Special Edition 1.8, amd64: goprint-v0.2.0-beta.7-astra1.8-amd64.deb.
- CentOS Stream 9, x86_64: goprint-0.2.0-0.beta.7.1.el9.x86_64.rpm.
- РЕД ОС 8, x86_64: goprint-0.2.0-0.beta.7.1.redos8.x86_64.rpm.

Укажите путь к скачанному файлу. Для Ubuntu и Astra Linux используйте `sudo apt install ./ИМЯ.deb`. Для CentOS Stream и РЕД ОС используйте `sudo dnf install ./ИМЯ.rpm`. Пакетный менеджер установит зависимости из настроенных репозиториев вашего дистрибутива. Пакеты выпуска публикуются с SHA256SUMS.

После первой установки выполните `sudo goprint-setup`, затем `sudo systemctl enable --now goprint`. Начальный токен хранится в `/etc/goprint/environment`. Откройте http://127.0.0.1:8631 на сервере или через SSH-туннель. Проверьте состояние командой `systemctl status goprint`. Для доступа из сети настройте HTTPS по [руководству администратора](ADMINISTRATOR.md).

При обновлении сохраните резервную копию БД, каталога данных и настроек. После установки пакета выполните `sudo systemctl restart goprint`. Очередь хранится в `/var/lib/goprint`, изменённый файл конфигурации обрабатывается штатным механизмом менеджера пакетов. После обновления проверьте токен, доступ к очереди и тестовую печать. Для серверов с особым режимом защиты проведите отдельную проверку в своей конфигурации.

Универсальные Linux-архивы для amd64 и arm64 тоже доступны. Порядок установки из архива приведён в руководстве администратора.
