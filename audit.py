import json
import os
import re
import subprocess
from datetime import datetime
#библиотеки

def main():
    def run(args, timeout=30): #функция для выполнения команд
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=timeout) #выполняем команду
            return (r.stdout or "").strip() #возвращаем результат
        except Exception: #если произошла ошибка
            return ""

    def push(type, problem, details, fix):
        findings.append(
            {
                "тип": type,  #ошибка или предупреждение
                "проблема": problem,
                "детали": details,
                "рекомендация": fix,
            }
        )

    def first_lines(text, n=5): #функция для вывода первых n строк
        lines = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                lines.append(line)
            if len(lines) >= n:
                break
        return lines

    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S") #время
    findings = []

    print("Автоаудит Linux")
    print("Время:", t)
    if os.geteuid() != 0:
        print("Запущено без sudo. Что-то может не вывестись.\n") #выводим сообщение о том, что запущено без sudo

#права (777/666)
    for d in ("/etc", "/var", "/home"):
        out = run(["find", d, "-type", "f", "-perm", "-0777", "-print"], timeout=30) #команда поиска файлов с правами 777
        if out:
            push(
                "ошибка",
                "Опасные права 777",
                "Где: "
                + d
                + "\nПримеры:\n- "
                + "\n- ".join(first_lines(out)),
                "снизить права (обычно chmod 644 для файлов, chmod 755 для каталогов).",
            )

        out = run(["find", d, "-type", "f", "-perm", "-0666", "-print"], timeout=30) #команда поиска файлов с правами 666
        if out:
            push( #добавляем найденные проблемы в список
                "предупреждение",
                "Права 666 (всем можно писать)",
                "Где: "
                + d
                + "\nПримеры:\n- "
                + "\n- ".join(first_lines(out)),
                "снизить права (обычно chmod 644).",
            )

#файлы с секретами
    kw = re.compile(r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|key=)", re.I) #регулярное выражение для поиска секретов
    for d in ("/etc", "/home"):
        files = run(["find", d, "-type", "f", "-perm", "-0004", "-size", "-200k", "-print"], timeout=30) #команда поиска файлов с правами 0004
        if not files:
            continue

        hits = [] #список найденных файлов
        for path in files.splitlines():
            if len(hits) >= 10: #если найдено 10 файлов
                break 
            try: #если файл не открывается
                with open(path, "r", encoding="utf-8", errors="ignore") as f: #открываем файл
                    chunk = f.read(4000) #читаем файл
            except Exception:
                continue
            if kw.search(chunk): #если в файле есть секрет
                hits.append(path) #добавляем файл в список

        if hits:
            push( #добавляем найденные проблемы в список
                "предупреждение",
                "Похоже на секреты в доступных всем файлах",
                "Где: " + d + "\nПримеры:\n- " + "\n- ".join(hits[:5]),
                "проверить содержимое, убрать секреты, снизить права (команда chmod 600/640).",
            )

#сеть (порты + бд)
    ss = run(["ss", "-tulpn"]) #команда поиска портов
    if not ss:
        push(
            "предупреждение",
            "Не получилось прочитать порты (ss)",
            "Команда ss не дала вывода.",
            "проверь iproute2 и права доступа.",
        )
    else: #если получилось прочитать порты
        listen_lines = [x for x in ss.splitlines() if "LISTEN" in x]
        joined = "\n".join(listen_lines) #соединяем строки
        if ":23" in joined:
            push("ошибка", "Открыт Telnet (23)", "Найден LISTEN на порту 23.", "Отключить telnet и закрыть порт (ufw deny 23).")
        if ":21" in joined:
            push("предупреждение", "Открыт FTP (21)", "Найден LISTEN на порту 21.", "Если не нужен — отключить и закрыть порт (ufw deny 21).")
        if ":445" in joined or ":139" in joined:
            push("предупреждение", "Открыт SMB (139/445)", "Найдены LISTEN на SMB-портах.", "Если не нужен — отключить samba и закрыть порты.")
        if ":3306" in joined and "127.0.0.1:3306" not in joined and "[::1]:3306" not in joined:
            push("предупреждение", "MySQL доступен не только локально", "Порт 3306 слушает не только localhost.", "Ограничить bind-address=127.0.0.1 или firewall.")

#пакеты и версии (dpkg)
    pkgs = run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"]) #команда поиска пакетов
    if not pkgs: #если не получилось получить список пакетов
        push( #добавляем найденные проблемы в список
            "предупреждение",
            "Не получилось получить список пакетов",
            "dpkg-query не дал вывода.",
            "проверь, что это Debian/Kali/Ubuntu и доступен dpkg.",
        )
    else: #если получилось получить список пакетов
        interesting = { #популярные пакеты
            "openssh-server",
            "apache2",
            "nginx",
            "mysql-server",
            "mariadb-server",
            "vsftpd",
            "telnetd",
            "samba",
        }
        found = [] #список найденных пакетов
        for line in pkgs.splitlines(): #делим строку на части
            pkg = line.split("\t", 1)[0]
            if pkg in interesting: #если пакет в списке популярных
                found.append(line)

        if found: #если найдены популярные пакеты
            push(
                "предупреждение",
                "Установлены популярные сетевые пакеты",
                "Нашлось:\n- " + "\n- ".join(found),
                "проверь актуальность версий и отключи ненужные сервисы.",
            )

    kernel = run(["uname", "-r"]) #команда поиска версии ядра
    if kernel: #если получилось прочитать версию ядра
        push("предупреждение", "Версия ядра", kernel, "если ядро старое — обновить пакеты/ядро (apt update && apt upgrade).")

#вывод и джсон
    findings.sort(key=lambda x: {"ошибка": 0, "предупреждение": 1}.get(x["тип"], 9))
    print("Найдено:", len(findings))
    for i, f in enumerate(findings, 1): #выводим найденные проблемы
        print(f"\n{i}) [{f['тип']}] {f['проблема']}")
        if f.get("детали"): #если есть детали
            for line in str(f["детали"]).splitlines(): #делим строку на части
                print("   ", line)
        print("   Что делать:", f["рекомендация"]) #выводим рекомендации

    with open("report.json", "w", encoding="utf-8") as fp: #сохраняем отчет в джсон
        json.dump({"время": t, "всего": len(findings), "пункты": findings}, fp, indent=2, ensure_ascii=False)
    print("\nОтчет сохранен в report.json") #выводим сообщение о сохранении отчета


if __name__ == "__main__":
    main()
