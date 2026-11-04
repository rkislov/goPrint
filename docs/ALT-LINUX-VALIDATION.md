# Проверка GoPrint с systemd на ALT Linux

4 ноября 2026 г. Выпуск v0.2.0-beta.6, обновление с v0.2.0-beta.5. Автор: Кислов Роман Сергеевич.

## Стенд

Полноценные виртуальные машины QEMU с собственными ядром, загрузчиком, диском и systemd как PID 1. Контейнеры для этой проверки не используются. ARM64 запускается с HVF и UEFI, x86_64 - с TCG и BIOS. Машины имеют отдельные диски и cloud-init seed; доступ SSH разрешён только через loopback хоста.

- ALT p10 aarch64: ядро 6.1.186-un-def-alt1, systemd 249.17-alt2.
- ALT p10 x86_64: ядро 6.1.186-un-def-alt1, systemd 249.17-alt2.
- ALT p11 aarch64: ядро 6.12.112-6.12-alt1, systemd 258.9-alt1.
- ALT p11 x86_64: ядро 6.12.110-6.12-alt1, systemd 257.9-alt1.

Официальные cloud-образы загружены с download.basealt.ru, проверены по опубликованным SHA256SUMS. Зависимости устанавливаются из соответствующей ветки. Доступ к зеркалу в изолированном стенде идёт через SSH-туннель с сохранением проверки HTTPS-сертификата и репозиторных контрольных сумм. В рабочей сети туннель не требуется.

## Проверки

Используется штатный RPM-unit без drop-in и изменения ExecStart. ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes и NoNewPrivileges=yes не отключаются. Проверяются свойства systemd и фактические UID процесса, NoNewPrivs, read-only корневой mount и отдельный /tmp в его пространстве имён.

На каждой машине выполняется полный цикл:

1. Установка beta.5 через apt-get с разрешением зависимостей. RPM сам не включает и не запускает службу.
2. goprint-setup, повторный запуск без смены токена, права конфигурации 0640 и каталога данных 0700.
3. enable --now, API, остановка и запуск с сохранением отложенного задания.
4. Преобразование PDF через синтетический PPD в PostScript и передача локальному TCP-приёмнику с проверкой маркера PPD.
5. Перезагрузка ОС, новый boot ID, автозапуск, сохранение очереди и повторная печать.
6. Обновление до beta.6 без смены токена и очереди. PID активной службы сохраняется; новая версия запускается явным restart администратора.
7. SIGKILL процесса, автоматический Restart=on-failure и сохранение задания.
8. Перезагрузка ОС с beta.6, автозапуск и печать сохранённого задания.
9. Удаление RPM во время работы, остановка службы, сохранение данных, учётной записи и конфигурации/.rpmsave. Повторная установка, восстановление конфигурации, запуск и печать оставшегося задания.

Каждый этап выдаёт PASS с версией RPM, архитектурой, ядром и systemd. Запись о SIGKILL в журнале ожидаема при проверке аварийного восстановления.

## Воспроизведение

Скрипт packaging/altlinux/systemd-smoke.py предназначен только для одноразовой VM: создаёт задания, перезапускает и аварийно завершает процесс службы, удаляет пакет. Не запускайте на рабочем сервере. Скопируйте весь каталог packaging/altlinux из тега выпуска и оба RPM своей ветки/архитектуры. Обновите индексы apt. Все команды выполняются внутри VM от root.

```sh
python3 packaging/altlinux/systemd-smoke.py prepare /path/to/old.rpm
systemctl reboot
```

После входа:

```sh
python3 packaging/altlinux/systemd-smoke.py boot
python3 packaging/altlinux/systemd-smoke.py upgrade /path/to/new.rpm
systemctl reboot
```

После следующего входа:

```sh
python3 packaging/altlinux/systemd-smoke.py boot
python3 packaging/altlinux/systemd-smoke.py remove /path/to/new.rpm
systemctl status goprint --no-pager
```

Служебное состояние теста хранится в /root/goprint-systemd-smoke.json с правами 0600. Токен не выводится и не включается в отчёт.

## Границы

Испытания относятся к указанным обычным cloud-образам p10/p11, а не сертифицированным редакциям ALT СП и корпоративным модификациям. В ARM cloud-образе p11 отдельно обнаружен сбой неиспользуемого getty@ttyS0 из-за отсутствия порта; он не относится к GoPrint. Состояние goprint.service проверяется отдельно.

TCP-приёмник подтверждает фильтрацию и передачу, но не физический выход бумаги. Реальные МФУ, Windows/AD SSO, Samba, SMTP, антивирус и политики безопасности организации требуют отдельного пилота.

## Образы и SHA-256

- [alt-p10-cloud-aarch64.qcow2](https://download.basealt.ru/pub/distributions/ALTLinux/p10/images/cloud/aarch64/alt-p10-cloud-aarch64.qcow2): `a2fba4530403a2392668da4ef41ede569cb657df31c8cb4c4b51103730bcfcb6`.

- [alt-p10-cloud-x86_64.qcow2](https://download.basealt.ru/pub/distributions/ALTLinux/p10/images/cloud/x86_64/alt-p10-cloud-x86_64.qcow2): `c01afebf1ad93e28071f259b2ebe16ed4f1b98f5fdb8c1ea8f50b9a1d8db11f0`.

- [alt-p11-cloud-aarch64.qcow2](https://download.basealt.ru/pub/distributions/ALTLinux/p11/images/cloud/aarch64/alt-p11-cloud-aarch64.qcow2): `a9bfdf392cea5f60be6c0eb2335e3f19546fff67096448e172447cc1e527a73e`.

- [alt-p11-cloud-x86_64.qcow2](https://download.basealt.ru/pub/distributions/ALTLinux/p11/images/cloud/x86_64/alt-p11-cloud-x86_64.qcow2): `af76a6727849c1f4856d5b51a4a74e90e695724f4be505749a153fbebf61f370`.
