# EvilGuard by Hex Bomb team

## Кирилл Южаков, Ксения Кравчук, Панков Георгий
### Проектный практикум (февраль-март 2025)

Версия EvilGuard, написанная полностью на Java. 
Это облегчённая версия приложения - в ней работают не все функции EvilGuard. 

> [!NOTE]
> ### Логика работы
> - Ищем паттерны (строки файла *.exe)
> - Отправляем на VirusTotal
> - Отправляем отчёт пользователю


# Скачать:
- Windows:
[Версия для windows](https://github.com/KirillYuzh/EvilGuard-Java/releases/download/main/EvilGuard-Java-Windows.exe)

> [!TIP]
> Если SmartScreen блокирует запуск:
> 1. Нажмите "Подробнее" в предупреждении
> 2. Выберите "Выполнить в любом случае

- MacOS:
[Версия для macOS](https://github.com/KirillYuzh/EvilGuard-Java/releases/download/main/EvilGuard-Java-MacOS.dmg)

> [!TIP]
> После скачивания:
> 1. Откройте Terminal
> 2. Выполните:  
> ``` bash
>   xattr -cr EvilGuard-Java-MacOS.dmg  # Удаляет карантинные атрибуты
>   open EvilGuard-Java-MacOS.dmg       # Открывает образ
>   cd /Volumes/EvilGuard-Java/
>   chmod +x Install.command
>   ./Install.command
> ```

- Linux (debian):
[Версия для debian](https://github.com/KirillYuzh/EvilGuard-Java/releases/download/main/EvilGuard-Java-Linux.deb)

> [!TIP]
> Установка после скачивания:
> ``` bash
> sudo dpkg -i EvilGuard-Java.deb
> ```
