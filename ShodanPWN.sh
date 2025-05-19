#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API_DELAY=10
MAX_CVES=20

echo -e "${GREEN}"
cat << "EOF"
   _____ __              __            ____ _       ___   __
  / ___// /_  ____  ____/ /___ _____  / __ \ |     / / | / /
  \__ \/ __ \/ __ \/ __  / __ `/ __ \/ /_/ / | /| / /  |/ /
 ___/ / / / / /_/ / /_/ / /_/ / / / / ____/| |/ |/ / /|  /
/____/_/ /_/\____/\__,_/\__,_/_/ /_/_/     |__/|__/_/ |_/
EOF
echo -e "${NC}"

check_deps() {
    command -v dig &>/dev/null || { echo -e "${RED}[!] Требуется dig (bind-utils/dnsutils)${NC}"; exit 1; }
    command -v curl &>/dev/null || { echo -e "${RED}[!] Требуется curl${NC}"; exit 1; }
    command -v jq &>/dev/null || { echo -e "${RED}[!] Требуется jq${NC}"; exit 1; }
    command -v searchsploit &>/dev/null || echo -e "${YELLOW}[!] searchsploit не найден (рекомендуется установить ExploitDB)${NC}"
}

safe_curl() {
    local url=$1
    local max_retries=3
    local retry_count=0
    local result

    while [ $retry_count -lt $max_retries ]; do
        result=$(curl -s "$url")
        if [ $? -eq 0 ]; then
            echo "$result"
            return 0
        fi
        retry_count=$((retry_count+1))
        sleep 1
    done

    echo -e "${YELLOW}[!] Ошибка при запросе к $url после $max_retries попыток${NC}" >&2
    return 1
}

get_cvss_score() {
    local cve=$1
    echo -e "\n${BLUE}[+] CVSS Score:${NC}"

    local nvd_data=$(safe_curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}")
    if [ $? -ne 0 ]; then
        echo "Ошибка при получении данных"
        return
    fi

    # Попробуем сначала получить CVSS v3.1
    local cvss_v3=$(echo "$nvd_data" | jq -r '.vulnerabilities[].cve.metrics.cvssMetricV31?[0].cvssData | "\(.baseScore) (\(.baseSeverity))"' 2>/dev/null)

    if [ -n "$cvss_v3" ] && [ "$cvss_v3" != "null (null)" ]; then
        echo "$cvss_v3"
    else
        # Если нет v3.1, попробуем получить v2.0
        local cvss_v2=$(echo "$nvd_data" | jq -r '.vulnerabilities[].cve.metrics.cvssMetricV2?[0].cvssData | "\(.baseScore) (\(.baseSeverity))"' 2>/dev/null)
        if [ -n "$cvss_v2" ] && [ "$cvss_v2" != "null (null)" ]; then
            echo "$cvss_v2 (CVSS v2.0)"
        else
            echo "Данные CVSS не найдены"
        fi
    fi

    sleep $API_DELAY
}

get_nvd_description() {
    local cve=$1
    echo -e "\n${BLUE}[+] NVD Description:${NC}"

    local nvd_data=$(safe_curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}")
    if [ $? -ne 0 ]; then
        echo "Ошибка при получении данных"
        return
    fi

    local description=$(echo "$nvd_data" | jq -r '.vulnerabilities[].cve.descriptions[] | select(.lang == "en").value' 2>/dev/null)

    if [ -n "$description" ] && [ "$description" != "null" ]; then
        echo "$description" | fold -s -w 80 # Перенос строк для удобства чтения
    else
        echo "Описание не найдено в NVD"
    fi

    # Выводим ссылки на дополнительные ресурсы
    echo -e "\n${BLUE}[+] Дополнительные ресурсы:${NC}"
    echo "$nvd_data" | jq -r '.vulnerabilities[].cve.references[].url' 2>/dev/null | \
    grep -i -E 'exploit|poc|github|metasploit|code|advisory|blog|analysis' | \
    sort -u | head -5

    sleep $API_DELAY
}

get_trickest_cve() {
    local cve=$1
    local year=$(echo "$cve" | cut -d'-' -f2)

    echo -e "\n${BLUE}[+] Trickest CVE Content:${NC}"
    local raw_url="https://raw.githubusercontent.com/trickest/cve/main/$year/$cve.md"

    local content=$(safe_curl "$raw_url")
    if [ $? -ne 0 ]; then
        echo "Ошибка при получении данных"
        return
    fi

    if [ -n "$content" ] && [[ ! "$content" =~ "404: Not Found" ]]; then
        # Выводим только полезные части (первые 20 строк)
        echo "$content" | grep -vE '^!\[|^### \[' | head -n 20 | sed 's/^/  /'
        echo -e "\n${YELLOW}[...] Полный файл: $raw_url${NC}"
    else
        echo "Файл не найден в репозитории Trickest"
    fi

    sleep $API_DELAY
}

get_exploit_sources() {
    local cve=$1

    # Локальный ExploitDB
    if command -v searchsploit &>/dev/null; then
        echo -e "\n${BLUE}[+] ExploitDB:${NC}"
        local results=$(searchsploit --cve "$cve" --id 2>/dev/null)
        if [ -n "$results" ]; then
            echo "$results"
            echo -e "\n${BLUE}[+] Пути к эксплойтам:${NC}"
            searchsploit --cve "$cve" --path 2>/dev/null || echo "Файлы не найдены"
        else
            echo "Не найдено"
        fi
    fi

    # GitHub PoC
    echo -e "\n${BLUE}[+] GitHub PoC:${NC}"
    local gh_results=$(safe_curl "https://api.github.com/search/repositories?q=${cve}+exploit+OR+POC&sort=updated&per_page=3")
    if [ $? -eq 0 ]; then
        echo "$gh_results" | jq -r '.items[] | select(.fork == false) | "\(.html_url) - \(.description)"' 2>/dev/null || echo "Не найдено рабочих PoC"
    else
        echo "Ошибка при запросе к GitHub API"
    fi

    sleep $API_DELAY
}

main() {
    check_deps

    read -p "Введите домен/IP: " target

    # Получаем IP
    echo -e "\n${BLUE}[*] Определяем IP...${NC}"
    if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip=$target
    else
        ip=$(dig +short "$target" | head -n1)
        [ -z "$ip" ] && ip=$(dig +short AAAA "$target" | head -n1)  # Попробуем IPv6, если IPv4 не найден
    fi

    [ -z "$ip" ] && { echo -e "${RED}[!] Не удалось получить IP${NC}"; exit 1; }
    echo -e "${GREEN}[+] IP: $ip${NC}"

    # Проверяем уязвимости
    echo -e "\n${BLUE}[*] Проверяем Shodan InternetDB...${NC}"
    local data=$(safe_curl "https://internetdb.shodan.io/$ip")
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Ошибка при запросе к Shodan InternetDB${NC}"
        exit 1
    fi

    echo "$data" | jq

    local cves=$(echo "$data" | jq -r '.vulns[]?' 2>/dev/null)
    [ -z "$cves" ] && { echo -e "${GREEN}[+] Уязвимостей не найдено${NC}"; exit 0; }

    # Ограничиваем количество обрабатываемых CVE
    local cve_count=$(echo "$cves" | wc -l)
    if [ $cve_count -gt $MAX_CVES ]; then
        echo -e "\n${YELLOW}[!] Найдено $cve_count CVE. Ограничение вывода до $MAX_CVES наиболее актуальных.${NC}"
        cves=$(echo "$cves" | head -n $MAX_CVES)
    fi

    echo -e "\n${RED}=== НАЙДЕННЫЕ CVE (${cve_count}) ==="
    for cve in $cves; do
        echo -e "\n${RED}▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
        echo -e "█ ${cve}"
        echo -e "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀${NC}"

        get_cvss_score "$cve"
        get_nvd_description "$cve"
        get_exploit_sources "$cve"
        get_trickest_cve "$cve"
    done

    if [ $cve_count -gt $MAX_CVES ]; then
        echo -e "\n${YELLOW}[!] Показано $MAX_CVES из $cve_count найденных CVE. Для полного списка проверьте вручную.${NC}"
    fi
}

main
