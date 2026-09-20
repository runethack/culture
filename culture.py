#!/usr/bin/env python3
# culture.py - автоматическая разведка

import subprocess
import sys
import os
import re
import json
import time
import socket
import argparse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


STATUS_MEANING = {
    '200': 'есть, доступно',
    '201': 'есть, создано',
    '204': 'есть, без содержимого',
    '301': 'переезд навсегда (смотри куда редиректит)',
    '302': 'временный редирект',
    '307': 'временный редирект (метод сохраняется)',
    '308': 'постоянный редирект (метод сохраняется)',
    '400': 'есть, но неправильный запрос',
    '401': 'есть, нужна авторизация',
    '403': 'есть, но запрещено (можно попробовать обход)',
    '405': 'есть, но не тот метод (роут живой)',
    '418': 'есть, я чайник (прикол сервера)',
    '429': 'есть, но лимит запросов',
    '500': 'есть, но падает (интересно)',
    '502': 'есть, но шлюз сломан',
    '503': 'есть, но сервис недоступен',
    '504': 'есть, но таймаут шлюза',
    'ERR': 'не ответил',
}


DANGEROUS_PATHS = {
    '/.git': 'открыт git-репозиторий, можно слить исходники',
    '/.git/config': 'конфиг git, там могут быть креды',
    '/.env': 'файл окружения, там пароли/токены',
    '/.env.backup': 'бэкап .env, часто без защиты',
    '/.htaccess': 'конфиг apache, может раскрыть правила',
    '/phpinfo.php': 'phpinfo, раскрывает всю конфигу сервера',
    '/info.php': 'phpinfo, сливает версии и модули',
    '/admin': 'админка, часто слабая защита',
    '/admin.php': 'админка php, часто брутится',
    '/wp-admin': 'админка wordpress',
    '/wp-login.php': 'логин wordpress',
    '/phpmyadmin': 'веб-морда mysql, часто пустая',
    '/pma': 'phpmyadmin короткий путь',
    '/adminer': 'adminer, веб-морда БД',
    '/backup': 'папка бэкапов, часто дампы БД',
    '/backups': 'папка бэкапов',
    '/db': 'может быть дамп БД',
    '/sql': 'может быть sql-файл',
    '/server-status': 'apache status, раскрывает запросы',
    '/actuator': 'spring boot, могут быть env/heapdump',
    '/actuator/health': 'spring health, безобидно но палит стек',
    '/console': 'консоль, потенциально RCE',
    '/shell': 'шелл, если открыт — полный доступ',
    '/.ssh': 'ключи ssh, если открыто — катастрофа',
}


# Юзер-агенты для авто-подбора лучшего
USER_AGENTS = {
    'chrome_linux':  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'chrome_win':    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'firefox':       'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'safari':        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'googlebot':     'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'bingbot':       'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'curl':          'curl/8.0.1',
    'python':        'python-requests/2.31.0',
}


class ProgressBar:
    def __init__(self, total, prefix='Скан'):
        self.total = total
        self.done = 0
        self.prefix = prefix
        self.lock = threading.Lock()
        self.current = ''

    def set_current(self, name):
        with self.lock:
            self.current = name
            self._draw()

    def tick(self):
        with self.lock:
            self.done += 1
            self._draw()

    def _draw(self):
        filled = int(30 * self.done / self.total) if self.total else 0
        bar = '#' * filled + '.' * (30 - filled)
        line = f"\r{Colors.CYAN}[{bar}] {self.done}/{self.total} {self.current:<15}{Colors.END}"
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self):
        self.done = self.total
        self._draw()
        sys.stdout.write('\n')
        sys.stdout.flush()


class CultureScanner:
    def __init__(self, use_json=False):
        self.target = None
        self.output_dir = None
        self.results = {}
        self.use_json = use_json
        self.best_ua = USER_AGENTS['chrome_linux']  # по дефолту
        self.tools = {
            'curl':         ['curl', '--version'],
            'nmap':         ['nmap', '--version'],
            'subfinder':    ['subfinder', '-version'],
            'whois':        ['whois', '--version'],
            'dig':          ['dig', '-v'],
            'whatweb':      ['whatweb', '--version'],
            'wafw00f':      ['wafw00f', '--version'],
            'theHarvester': ['theHarvester', '-h'],
            'nuclei':       ['nuclei', '-version'],
            'httpx':        ['httpx', '-version'],
            'sqlmap':       ['sqlmap', '--version'],
            'nikto':        ['nikto', '-Version'],
            'gobuster':     ['gobuster', 'version'],
            'ffuf':         ['ffuf', '-V'],
        }
        self.available = {}
        self.missing = []

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def print_header(self):
        self.clear_screen()
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.PURPLE}              CULTURE - АВТОРАЗВЕДКА{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.YELLOW}    Цель: IP или домен | Мульти-инструмент{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")

    def check_tools(self):
        self.available = {}
        self.missing = []
        for name, cmd in self.tools.items():
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
                self.available[name] = True
            except Exception:
                self.available[name] = False
                self.missing.append(name)

    def show_tools_status(self):
        print(f"{Colors.BOLD}ДОСТУПНЫЕ ИНСТРУМЕНТЫ:{Colors.END}")
        for name, ok in self.available.items():
            mark = f"{Colors.GREEN}[+]{Colors.END}" if ok else f"{Colors.RED}[-]{Colors.END}"
            print(f"  {mark} {name}")
        if self.missing:
            print(f"\n{Colors.YELLOW}Отсутствуют: {', '.join(self.missing)}{Colors.END}")
        print()

    def show_main_menu(self):
        while True:
            self.print_header()
            print(f"{Colors.BOLD}ГЛАВНОЕ МЕНЮ:{Colors.END}")
            print(f"  {Colors.GREEN}1.{Colors.END} Сканировать домен")
            print(f"  {Colors.GREEN}2.{Colors.END} Сканировать IP")
            print(f"  {Colors.GREEN}3.{Colors.END} Сканировать из файла")
            print(f"  {Colors.GREEN}4.{Colors.END} История")
            print(f"  {Colors.GREEN}5.{Colors.END} Проверить инструменты")
            print(f"  {Colors.RED}6.{Colors.END} Выход")
            print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
            choice = input(f"{Colors.BOLD}Выбор (1-6): {Colors.END}").strip()

            if choice == '1':
                d = input(f"{Colors.YELLOW}Домен: {Colors.END}").strip()
                if not d:
                    print(f"{Colors.RED}Пусто!{Colors.END}"); time.sleep(1); continue
                self.target = d
                self.run_scan()
            elif choice == '2':
                ip = input(f"{Colors.YELLOW}IP: {Colors.END}").strip()
                if not ip:
                    print(f"{Colors.RED}Пусто!{Colors.END}"); time.sleep(1); continue
                self.target = ip
                self.run_scan()
            elif choice == '3':
                self.scan_from_file()
            elif choice == '4':
                self.show_history()
            elif choice == '5':
                self.check_tools()
                self.print_header()
                self.show_tools_status()
                input(f"{Colors.CYAN}Enter для возврата...{Colors.END}")
            elif choice == '6':
                print(f"\n{Colors.GREEN}Выход.{Colors.END}")
                sys.exit(0)

    def scan_from_file(self):
        self.print_header()
        path = input(f"{Colors.YELLOW}Путь к файлу: {Colors.END}").strip()
        if not os.path.exists(path):
            print(f"{Colors.RED}Файл не найден!{Colors.END}"); time.sleep(1); return
        with open(path) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        if not targets:
            print(f"{Colors.RED}Пусто!{Colors.END}"); time.sleep(1); return
        print(f"{Colors.GREEN}Целей: {len(targets)}{Colors.END}\n")

        for i, t in enumerate(targets, 1):
            print(f"\n{Colors.BOLD}{Colors.PURPLE}>>> [{i}/{len(targets)}] {t}{Colors.END}")
            self.target = t
            self.run_scan(silent=False, wait=False)

        print(f"\n{Colors.GREEN}Все цели готовы. Enter...{Colors.END}")
        input()

    def run_scan(self, silent=False, wait=True):
        self.check_tools()

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = self.target.replace('.', '_').replace('/', '_').replace(':', '_')
        self.output_dir = f"culture_{safe}_{ts}"
        os.makedirs(self.output_dir, exist_ok=True)

        if not silent:
            print(f"\n{Colors.BOLD}ЦЕЛЬ: {Colors.YELLOW}{self.target}{Colors.END}")
            print(f"{Colors.BOLD}ПАПКА: {Colors.YELLOW}{self.output_dir}{Colors.END}\n")

        ip = self.resolve_target(self.target)

        # авто-подбор лучшего UA
        if not silent:
            print(f"{Colors.BOLD}ПОДБОР USER-AGENT...{Colors.END}")
        self.best_ua = self.pick_best_ua()
        if not silent:
            print(f"{Colors.GREEN}[+] лучший UA: {self.best_ua[:60]}...{Colors.END}\n")

        tasks = {
            'curl':         ('HTTP заголовки',       lambda: self.run_curl()),
            'nmap':         ('Порты и сервисы',      lambda: self.run_nmap(ip)),
            'subfinder':    ('Поддомены',            lambda: self.run_subfinder()),
            'whois':        ('WHOIS домена',         lambda: self.run_whois()),
            'dig':          ('DNS записи',           lambda: self.run_dig()),
            'whatweb':      ('Технологии сайта',     lambda: self.run_whatweb()),
            'wafw00f':      ('WAF детект',           lambda: self.run_wafw00f()),
            'theHarvester': ('Сбор email/имён',      lambda: self.run_harvester()),
            'nuclei':       ('Поиск уязвимостей',    lambda: self.run_nuclei()),
            'httpx':        ('Живые хосты/тех',      lambda: self.run_httpx()),
            'sqlmap':       ('SQL детект',           lambda: self.run_sqlmap()),
            'nikto':        ('Веб-сканер',           lambda: self.run_nikto()),
            'pathbrute':    ('Брутфорс путей',       lambda: self.run_pathbrute()),
            'apibrute':     ('Открытые API',         lambda: self.run_apibrute()),
            'crawl':        ('robots/sitemap',       lambda: self.run_crawl()),
            'authbrute':    ('OAuth/OpenID',         lambda: self.run_authbrute()),
        }

        active = {}
        for name, (desc, fn) in tasks.items():
            if not self.available.get(name) and name not in ('pathbrute', 'apibrute', 'crawl', 'authbrute'):
                self.results[name] = {'status': 'missing', 'output': 'инструмент не установлен'}
                if not silent:
                    print(f"{Colors.YELLOW}[!] {name} : не установлен, пропускаю{Colors.END}")
            else:
                active[name] = (desc, fn)

        total = len(active)
        if total == 0:
            if not silent:
                print(f"\n{Colors.RED}Ни одного инструмента не найдено.{Colors.END}")
            self.save_summary(silent)
            if not silent and wait:
                input(f"{Colors.CYAN}Enter...{Colors.END}")
            return

        bar = ProgressBar(total, prefix='Скан')
        print(f"\n{Colors.BOLD}ЗАПУСК {total} ЗАДАЧ:{Colors.END}\n")

        with ThreadPoolExecutor(max_workers=min(6, total)) as ex:
            futures = {}
            for name, (desc, fn) in active.items():
                bar.set_current(name)
                futures[ex.submit(fn)] = (name, desc)

            for fut in as_completed(futures):
                name, desc = futures[fut]
                bar.set_current(name)
                try:
                    out = fut.result() or '[нет вывода]'
                    self.results[name] = {'status': 'ok', 'output': out}
                    self.print_tool_result(name, desc, out, color=Colors.GREEN)
                except Exception as e:
                    self.results[name] = {'status': 'error', 'output': str(e)}
                    self.print_tool_result(name, desc, f'ошибка: {e}', color=Colors.RED)
                finally:
                    bar.tick()

        bar.finish()
        self.save_summary(silent)

        if not silent:
            print(f"\n{Colors.GREEN}[✓] ГОТОВО. Файлы: {self.output_dir}{Colors.END}")
            if wait:
                input(f"{Colors.CYAN}Enter...{Colors.END}")

    def print_tool_result(self, name, desc, output, color):
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        print(f"{color}{'='*60}{Colors.END}")
        print(f"{color}[+] {name}{Colors.END} ({desc})")
        print(f"{color}{'='*60}{Colors.END}")
        print(output)
        print()

    def resolve_target(self, target):
        try:
            socket.inet_aton(target)
            return target
        except OSError:
            pass
        try:
            return socket.gethostbyname(target)
        except Exception:
            return target

    def save_output(self, name, content):
        path = os.path.join(self.output_dir, f"{name}.txt")
        with open(path, 'w', errors='ignore') as f:
            f.write(content if isinstance(content, str) else str(content))
        return path

    # ----- авто-подбор лучшего User-Agent -----

    def pick_best_ua(self):
        """Стучится одним и тем же URL с разными UA и смотрит какой пробивает больше."""
        try:
            socket.inet_aton(self.target)
            url = f"https://{self.target}"
        except OSError:
            url = f"https://{self.target}"

        results = {}

        def probe(name, ua):
            try:
                r = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}|%{size_download}',
                     '-A', ua, '--max-time', '8', '-L', url],
                    capture_output=True, text=True, timeout=12)
                code, size = (r.stdout.split('|') + ['0', '0'])[:2]
                return name, ua, code, int(size or 0)
            except Exception:
                return name, ua, 'ERR', 0

        with ThreadPoolExecutor(max_workers=len(USER_AGENTS)) as ex:
            futures = [ex.submit(probe, n, u) for n, u in USER_AGENTS.items()]
            for fut in as_completed(futures):
                name, ua, code, size = fut.result()
                results[name] = (ua, code, size)

        # лучший — где код 200 и максимальный размер
        best_name, best_ua, best_score = None, USER_AGENTS['chrome_linux'], -1
        for name, (ua, code, size) in results.items():
            score = 0
            if code == '200':
                score = size
            elif code in ('301', '302'):
                score = size // 2
            if score > best_score:
                best_score = score
                best_ua = ua
                best_name = name

        return best_ua

    def ua_args(self):
        """Возвращает аргументы -A для curl."""
        return ['-A', self.best_ua]

    # ----- инструменты -----

    def run_curl(self):
        out = []
        for proto in ('http://', 'https://'):
            url = f"{proto}{self.target}"
            try:
                r = subprocess.run(
                    ['curl', '-I', '-L', '--max-time', '20', '-s',
                     '-w', '\nSTATUS:%{http_code} TIME:%{time_total}s IP:%{remote_ip}\n',
                     ] + self.ua_args() + [url],
                    capture_output=True, text=True, timeout=30)
                out.append(f"=== {url} ===\n{r.stdout or '[нет ответа]'}")
            except Exception as e:
                out.append(f"=== {url} ===\n[ошибка: {e}]")
        res = "\n".join(out)
        self.save_output('curl', res)
        return res

    def run_nmap(self, ip):
        try:
            r = subprocess.run(
                ['nmap', '-sV', '-sC', '-T4', '--top-ports', '1000', ip],
                capture_output=True, text=True, timeout=600)
            res = r.stdout or '[нет вывода]'
        except subprocess.TimeoutExpired:
            res = '[таймаут]'
        except Exception as e:
            res = f'[ошибка: {e}]'
        self.save_output('nmap', res)
        return res

    def run_subfinder(self):
        try:
            socket.inet_aton(self.target)
            return '[IP, subfinder не применяется]'
        except OSError:
            pass
        path = os.path.join(self.output_dir, 'subfinder.txt')
        try:
            subprocess.run(['subfinder', '-d', self.target, '-o', path, '-silent'],
                           capture_output=True, timeout=300)
            with open(path) as f:
                return f.read() or '[ничего не найдено]'
        except Exception as e:
            return f'[ошибка: {e}]'

    def run_whois(self):
        try:
            r = subprocess.run(['whois', self.target], capture_output=True, text=True, timeout=60)
            res = r.stdout or '[нет вывода]'
        except Exception as e:
            res = f'[ошибка: {e}]'
        self.save_output('whois', res)
        return res

    def run_dig(self):
        try:
            r = subprocess.run(['dig', '+short', self.target], capture_output=True, text=True, timeout=20)
            res = r.stdout or '[нет A-записей]'
        except Exception as e:
            res = f'[ошибка: {e}]'
        self.save_output('dig', res)
        return res

    def run_whatweb(self):
        try:
            r = subprocess.run(['whatweb', '-a', '3', self.target], capture_output=True, text=True, timeout=120)
            res = r.stdout or '[нет вывода]'
        except Exception as e:
            res = f'[ошибка: {e}]'
        self.save_output('whatweb', res)
        return res

    def run_wafw00f(self):
        try:
            r = subprocess.run(['wafw00f', self.target], capture_output=True, text=True, timeout=60)
            res = r.stdout or '[нет вывода]'
        except Exception as e:
            res = f'[ошибка: {e}]'
        self.save_output('wafw00f', res)
        return res

    def run_harvester(self):
        try:
            r = subprocess.run(['theHarvester', '-d', self.target, '-b', 'all', '-l', '200'],
                               capture_output=True, text=True, timeout=300)
            res = r.stdout or '[нет вывода]'
        except Exception as e:
            res = f'[ошибка: {e}]'
        self.save_output('theHarvester', res)
        return res

    def run_nuclei(self):
        try:
            r = subprocess.run(['nuclei', '-u', self.target, '-silent',
                                '-severity', 'low,medium,high,critical'],
                               capture_output=True, text=True, timeout=600)
            res = r.stdout or '[нет находок]'
        except Exception as e:
            res = f'[ошибка: {e}]'
        self.save_output('nuclei', res)
        return res

    def run_httpx(self):
        try:
            r = subprocess.run(['httpx', '-u', self.target, '-silent',
                                '-status-code', '-title', '-tech-detect',
                                '-H', f'User-Agent: {self.best_ua}'],
                               capture_output=True, text=True, timeout=60)
            res = r.stdout or '[нет ответа]'
        except Exception as e:
            res = f'[ошибка: {e}]'
        self.save_output('httpx', res)
        return res

    def run_sqlmap(self):
        url = self.target if self.target.startswith('http') else f"http://{self.target}"
        try:
            r = subprocess.run(['sqlmap', '-u', url, '--batch',
                                '--level=1', '--risk=1', '--smart',
                                '--user-agent', self.best_ua],
                               capture_output=True, text=True, timeout=300)
            res = r.stdout or '[нет вывода]'
        except Exception as e:
            res = f'[ошибка: {e}]'
        self.save_output('sqlmap', res)
        return res

    def run_nikto(self):
        url = self.target if self.target.startswith('http') else f"http://{self.target}"
        try:
            r = subprocess.run(['nikto', '-h', url, '-maxtime', '120',
                                '-useragent', self.best_ua],
                               capture_output=True, text=True, timeout=180)
            res = r.stdout or '[нет вывода]'
        except Exception as e:
            res = f'[ошибка: {e}]'
        self.save_output('nikto', res)
        return res

    def _detect_real_host(self):
        try:
            socket.inet_aton(self.target)
            is_ip = True
        except OSError:
            is_ip = False

        if not is_ip:
            return self.target

        try:
            ptr = socket.gethostbyaddr(self.target)[0]
            if ptr and not ptr.replace('.', '').isdigit():
                return ptr
        except Exception:
            pass

        for proto in ('http://', 'https://'):
            try:
                r = subprocess.run(
                    ['curl', '-s', '-I', '-L', '--max-time', '8',
                     '-w', '\nREDIR_HOST:%{url_effective}'] + self.ua_args() + [f"{proto}{self.target}"],
                    capture_output=True, text=True, timeout=12)
                out = r.stdout
                for line in out.split('\n'):
                    low = line.lower()
                    if low.startswith('location:'):
                        loc = line.split(':', 1)[1].strip()
                        host = loc.replace('https://', '').replace('http://', '')
                        host = host.split('/')[0].split(':')[0]
                        if host and host != self.target:
                            return host
            except Exception:
                continue

        return self.target

    def _base_url(self, real_host=None):
        host = real_host or self._detect_real_host()
        if host.startswith('http'):
            return host.rstrip('/')
        return f"https://{host}".rstrip('/')

    # ----- брутфорс путей с SPA-детектом -----

    def run_pathbrute(self):
        real_host = self._detect_real_host()
        if real_host != self.target:
            print(f"{Colors.YELLOW}[*] pathbrute: определён хост {real_host} для {self.target}{Colors.END}")

        base = self._base_url(real_host)

        paths = [
            '/api', '/api/', '/api/v1', '/api/v2', '/api/v3', '/api/v4',
            '/api/docs', '/api/swagger', '/api/swagger.json', '/api/openapi.json',
            '/api/health', '/api/status', '/api/version', '/api/users', '/api/user',
            '/api/admin', '/api/login', '/api/auth', '/api/token', '/api/config',
            '/graphql', '/graphiql', '/graphql/console',
            '/swagger', '/swagger/', '/swagger.json', '/swagger.yaml',
            '/swagger-ui', '/swagger-ui/', '/swagger-ui.html', '/swagger/index.html',
            '/openapi.json', '/openapi.yaml', '/api-docs', '/api-docs/',
            '/docs', '/docs/', '/redoc', '/redoc/',
            '/admin', '/admin/', '/admin/login', '/admin.php', '/admin.html',
            '/administrator', '/administrator/', '/adminpanel', '/admin_area',
            '/login', '/login/', '/signin', '/signin/', '/auth', '/auth/',
            '/oauth', '/oauth/', '/oauth/token', '/register', '/signup',
            '/panel', '/cpanel', '/controlpanel', '/dashboard', '/dashboard/',
            '/manage', '/manager', '/management', '/console', '/console/',
            '/wp-admin', '/wp-admin/', '/wp-login.php', '/wp-json', '/wp-json/',
            '/wp-config.php', '/wp-content', '/wp-content/', '/wp-includes',
            '/user', '/users', '/account', '/accounts', '/profile', '/profiles',
            '/settings', '/config', '/configuration', '/setup', '/install',
            '/backup', '/backups', '/backup.zip', '/backup.tar.gz', '/backup.sql',
            '/bak', '/old', '/tmp', '/temp', '/test', '/tests', '/testing',
            '/dev', '/debug', '/staging', '/private', '/secret', '/hidden',
            '/logs', '/log', '/error', '/errors', '/trace', '/version',
            '/status', '/health', '/healthz', '/ping', '/metrics', '/info',
            '/.git', '/.git/', '/.git/config', '/.git/HEAD', '/.svn', '/.hg',
            '/.env', '/.env.local', '/.env.backup', '/.env.example',
            '/.htaccess', '/.htpasswd', '/.DS_Store',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/security.txt',
            '/humans.txt', '/ads.txt',
            '/phpinfo.php', '/info.php', '/test.php', '/php.php',
            '/db', '/db/', '/database', '/sql', '/dump', '/dumps',
            '/phpmyadmin', '/phpmyadmin/', '/pma', '/pma/', '/adminer',
            '/adminer.php', '/mysql', '/mysql/',
            '/server-status', '/server-info', '/nginx_status',
            '/actuator', '/actuator/', '/actuator/health', '/actuator/info',
            '/actuator/env', '/actuator/heapdump', '/actuator/mappings',
            '/upload', '/uploads', '/files', '/download', '/downloads',
            '/static', '/assets', '/js', '/css', '/images', '/img', '/media',
            '/public', '/data', '/storage', '/cache',
            '/shell', '/cmd', '/exec', '/run', '/eval',
            '/api/internal', '/internal', '/intranet', '/vpn', '/proxy',
        ]

        found = []

        def check(path):
            url = base + path
            try:
                r = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w',
                     '%{http_code}|%{size_download}|%{redirect_url}|%{content_type}',
                     '-L', '--max-time', '8'] + self.ua_args() + [url],
                    capture_output=True, text=True, timeout=12)
                parts = (r.stdout.split('|') + ['', '', '', ''])[:4]
                code, size, redir, ct = parts
                return path, code, size, redir, ct
            except Exception:
                return path, 'ERR', '0', '', ''

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check, p): p for p in paths}
            for fut in as_completed(futures):
                path, code, size, redir, ct = fut.result()
                if code in ('200', '201', '204', '301', '302', '307', '308',
                            '400', '401', '403', '405', '418', '429',
                            '500', '502', '503', '504'):
                    found.append((code, path, size, redir, ct))

        found.sort(key=lambda x: (x[0], x[1]))

        # SPA-детект: собираем размеры 200-ок, ищем совпадения
        sizes_200 = {}
        for code, path, size, redir, ct in found:
            if code == '200' and size.isdigit():
                s = int(size)
                sizes_200.setdefault(s, []).append(path)

        # SPA если у 3+ путей одинаковый размер (fallback index.html)
        spa_sizes = {s for s, paths_list in sizes_200.items() if len(paths_list) >= 3}

        if not found:
            res = f'[ничего не найдено на {real_host}]'
        else:
            lines = [f"Хост: {real_host}",
                     f"User-Agent: {self.best_ua[:70]}",
                     f"Найдено путей: {len(found)}", "=" * 60]
            for code, path, size, redir, ct in found:
                meaning = STATUS_MEANING.get(code, 'неизвестный код')
                line = f"{code:>3}  {size:>8}b  {path:<40}  # {meaning}"
                if ct:
                    line += f"  [{ct.split(';')[0]}]"
                if redir:
                    line += f"\n       -> {redir}"
                if path in DANGEROUS_PATHS:
                    line += f"\n       !! {DANGEROUS_PATHS[path]}"
                # SPA-пометка
                if code == '200' and size.isdigit() and int(size) in spa_sizes:
                    line += f"\n       [похоже на SPA-заглушку: такой же размер у других путей]"
                lines.append(line)
            res = "\n".join(lines)

        self.save_output('pathbrute', res)
        return res

    # ----- robots.txt + sitemap.xml парсинг и проверка -----

    def run_crawl(self):
        base = self._base_url()
        found_paths = set()
        sources = []

        # robots.txt
        try:
            r = subprocess.run(
                ['curl', '-s', '--max-time', '10'] + self.ua_args() + [base + '/robots.txt'],
                capture_output=True, text=True, timeout=15)
            robots = r.stdout.strip()
            if robots and not robots.startswith('<'):
                sources.append(('robots.txt', robots))
                for line in robots.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    low = line.lower()
                    if low.startswith('disallow:') or low.startswith('allow:'):
                        p = line.split(':', 1)[1].strip()
                        if p and p != '/' and not p.startswith('*'):
                            found_paths.add(p)
                    elif low.startswith('sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        # sitemap: https://x.com/sitemap.xml (там двоеточие уже съедено)
                        if not sitemap_url.startswith('http'):
                            sitemap_url = line.split(' ', 1)[1].strip() if ' ' in line else sitemap_url
                        sources.append(('sitemap-link', sitemap_url))
        except Exception as e:
            sources.append(('robots-error', str(e)))

        # sitemap.xml
        for sm_url in [base + '/sitemap.xml'] + [u for s, u in sources if s == 'sitemap-link'][:3]:
            try:
                r = subprocess.run(
                    ['curl', '-s', '--max-time', '15'] + self.ua_args() + [sm_url],
                    capture_output=True, text=True, timeout=20)
                sm = r.stdout
                if not sm:
                    continue
                # вытаскиваем <loc>...</loc>
                locs = re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', sm)
                if locs:
                    sources.append(('sitemap.xml', sm[:2000]))
                for loc in locs:
                    # локалку -> путь
                    m = re.match(r'https?://[^/]+(/.*)?', loc)
                    if m:
                        p = m.group(1) or '/'
                        if p != '/':
                            found_paths.add(p)
            except Exception:
                pass

        # чистим и берём топ-300 чтоб не вечность
        found_paths = sorted(p for p in found_paths if p and len(p) < 200)[:300]

        # проверяем каждый
        checks = []

        def check(path):
            url = base + path
            try:
                r = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w',
                     '%{http_code}|%{size_download}|%{content_type}',
                     '-L', '--max-time', '8'] + self.ua_args() + [url],
                    capture_output=True, text=True, timeout=12)
                code, size, ct = (r.stdout.split('|') + ['', '', ''])[:3]
                return path, code, size, ct
            except Exception:
                return path, 'ERR', '0', ''

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check, p): p for p in found_paths}
            for fut in as_completed(futures):
                checks.append(fut.result())

        checks.sort(key=lambda x: (x[1], x[0]))

        # собираем отчёт
        lines = []
        lines.append(f"Хост: {base}")
        lines.append("=" * 60)

        # что нашли в robots/sitemap
        for name, content in sources:
            if name.endswith('error'):
                continue
            lines.append(f"\n--- {name} ---")
            if len(content) > 1500:
                lines.append(content[:1500] + '\n[...обрезано...]')
            else:
                lines.append(content)

        lines.append("")
        lines.append("=" * 60)
        lines.append(f"ПРОВЕРКА НАЙДЕННЫХ ПУТЕЙ ({len(checks)}):")
        lines.append("=" * 60)

        for path, code, size, ct in checks:
            meaning = STATUS_MEANING.get(code, 'неизвестный код')
            line = f"{code:>3}  {size:>8}b  {path:<50}  # {meaning}"
            if ct:
                line += f"  [{ct.split(';')[0]}]"
            if path in DANGEROUS_PATHS:
                line += f"\n       !! {DANGEROUS_PATHS[path]}"
            lines.append(line)

        if not checks:
            lines.append("[ничего не найдено]")

        res = "\n".join(lines)
        self.save_output('crawl', res)
        return res

    # ----- OAuth/OpenID/JWT + проверка защищённых роутов без токена -----

    def run_authbrute(self):
        base = self._base_url()

        # 1) OAuth + OpenID эндпоинты
        auth_paths = [
            # OAuth 2.0
            '/oauth/authorize', '/oauth/token', '/oauth/revoke', '/oauth/introspect',
            '/oauth2/authorize', '/oauth2/token', '/oauth2/revoke', '/oauth2/introspect',
            '/oauth/access_token', '/oauth/refresh',
            '/connect/authorize', '/connect/token', '/connect/revoke',
            '/login/oauth/authorize', '/login/oauth/access_token',
            '/services/oauth2/authorize', '/services/oauth2/token',
            '/auth/oauth/authorize', '/auth/oauth/token',
            # OpenID Connect
            '/.well-known/openid-configuration',
            '/.well-known/oauth-authorization-server',
            '/.well-known/jwks.json',
            '/.well-known/webfinger',
            '/.well-known/security.txt',
            # JWT/token эндпоинты
            '/jwt', '/token', '/tokens', '/api/token', '/api/tokens',
            '/auth/token', '/auth/jwt', '/api/auth/token',
            '/api/v1/token', '/api/v1/auth/token',
            '/refresh', '/api/refresh', '/auth/refresh',
            # login/callback
            '/auth/login', '/auth/callback', '/auth/logout',
            '/login/callback', '/oauth/callback',
            '/saml/login', '/saml/metadata', '/sso', '/sso/login',
        ]

        # 2) защищённые роуты — стучимся БЕЗ Authorization
        protected_paths = [
            '/api/me', '/api/v1/me', '/api/user', '/api/v1/user',
            '/api/profile', '/api/v1/profile',
            '/api/account', '/api/v1/account',
            '/api/admin', '/api/v1/admin',
            '/api/settings', '/api/v1/settings',
            '/api/config', '/api/v1/config',
            '/api/dashboard', '/api/v1/dashboard',
            '/me', '/profile', '/account', '/admin', '/dashboard',
            '/api/private', '/api/v1/private',
            '/api/internal', '/api/v1/internal',
            '/api/users', '/api/v1/users',
            '/api/orders', '/api/v1/orders',
            '/api/payments', '/api/v1/payments',
            '/api/billing', '/api/v1/billing',
            '/api/keys', '/api/v1/keys',
            '/api/tokens', '/api/v1/tokens',
            '/api/sessions', '/api/v1/sessions',
        ]

        all_paths = auth_paths + protected_paths
        found = []

        def check(path):
            url = base + path
            try:
                r = subprocess.run(
                    ['curl', '-s', '-X', 'GET', '--max-time', '8',
                     '-H', 'Accept: application/json',
                     '-H', 'User-Agent: ' + self.best_ua,
                     '-w', '\n---HTTP_CODE:%{http_code}|SIZE:%{size_download}|CT:%{content_type}',
                     url],
                    capture_output=True, text=True, timeout=12)
                body = r.stdout
                if '---HTTP_CODE:' in body:
                    body, meta = body.rsplit('---HTTP_CODE:', 1)
                    code, rest = meta.split('|SIZE:', 1)
                    size, ct = rest.split('|CT:', 1)
                else:
                    code, size, ct = '0', '0', 'unknown'
                return path, code.strip(), size.strip(), ct.strip(), body.strip()
            except Exception:
                return path, 'ERR', '0', '', ''

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check, p): p for p in all_paths}
            for fut in as_completed(futures):
                path, code, size, ct, body = fut.result()
                if code in ('200', '201', '204', '301', '302', '307', '308',
                            '400', '401', '403', '405', '429', '500', '502', '503'):
                    found.append({
                        'path': path, 'code': code, 'size': size,
                        'ct': ct, 'body': body, 'is_auth': path in auth_paths
                    })

        found.sort(key=lambda x: (x['path']))

        if not found:
            res = '[ничего не найдено]'
        else:
            lines = [f"Хост: {base}",
                     f"Всего проверено: {len(all_paths)}",
                     f"Отозвалось: {len(found)}",
                     "=" * 60]

            # сначала опасные (200 без авторизации на защищённых)
            holes = []
            for item in found:
                if (not item['is_auth']
                        and item['code'] == '200'
                        and item['size'].isdigit()
                        and int(item['size']) > 0):
                    holes.append(item)

            if holes:
                lines.append("")
                lines.append(f"{Colors.RED if False else ''}!! ДЫРЫ ({len(holes)}): защищённые роуты отвечают 200 без токена")
                lines.append("-" * 60)
                for item in holes:
                    lines.append(f"  {item['code']}  {item['size']}b  {item['path']}")
                    lines.append(f"        content-type: {item['ct']}")
                    snippet = item['body'][:200].replace('\n', ' ')
                    lines.append(f"        первые байты: {snippet}")
                    lines.append("")

            lines.append("")
            lines.append(f"ПОЛНЫЙ СПИСОК ({len(found)}):")
            lines.append("=" * 60)

            for item in found:
                meaning = STATUS_MEANING.get(item['code'], 'неизвестный код')
                marker = '[auth]' if item['is_auth'] else '[prot]'
                line = f"{marker} {item['code']:>3}  {item['size']:>8}b  {item['path']:<45}  # {meaning}"
                if item['ct']:
                    line += f"  [{item['ct'].split(';')[0]}]"
                # пометка дыры
                if (not item['is_auth'] and item['code'] == '200'
                        and item['size'].isdigit() and int(item['size']) > 0):
                    line += f"\n        !! ДЫРА: отдаёт данные без авторизации"
                # для oauth покажем что отдал
                if item['is_auth'] and item['code'] == '200':
                    snippet = item['body'][:120].replace('\n', ' ')
                    if snippet:
                        line += f"\n        ответ: {snippet}"
                lines.append(line)

            res = "\n".join(lines)

        self.save_output('authbrute', res)
        return res

    # ----- apibrute (гео + пути, как было) -----

    def run_apibrute(self):
        try:
            socket.inet_aton(self.target)
            is_ip = True
        except OSError:
            is_ip = False

        geo_results = []

        if is_ip:
            geo_apis = [
                ('ip-api.com',       f'http://ip-api.com/json/{self.target}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query'),
                ('ipapi.co',         f'https://ipapi.co/{self.target}/json/'),
                ('ipinfo.io',        f'https://ipinfo.io/{self.target}/json'),
                ('ipwho.is',         f'https://ipwho.is/{self.target}'),
                ('freeipapi.com',    f'https://freeipapi.com/api/json/{self.target}'),
                ('ip.guide',         f'https://ip.guide/{self.target}'),
                ('api.iplocation.net', f'https://api.iplocation.net/?ip={self.target}'),
            ]

            def fetch(name, url):
                try:
                    r = subprocess.run(
                        ['curl', '-s', '--max-time', '10', '-A', self.best_ua, url],
                        capture_output=True, text=True, timeout=15)
                    return name, url, r.stdout.strip()
                except Exception as e:
                    return name, url, f'[ошибка: {e}]'

            with ThreadPoolExecutor(max_workers=7) as ex:
                futures = [ex.submit(fetch, n, u) for n, u in geo_apis]
                for fut in as_completed(futures):
                    name, url, body = fut.result()
                    if body and not body.startswith('[') and 'error' not in body[:40].lower():
                        geo_results.append({'source': name, 'url': url, 'data': body})

        real_host = self._detect_real_host()
        base = self._base_url(real_host)

        api_paths = [
            '/api', '/api/', '/api/v1', '/api/v1/', '/api/v2', '/api/v2/',
            '/api/v3', '/api/v3/',
            '/api/users', '/api/v1/users', '/api/v2/users',
            '/api/user', '/api/v1/user',
            '/api/accounts', '/api/v1/accounts',
            '/api/profile', '/api/v1/profile',
            '/api/me', '/api/v1/me',
            '/api/admin', '/api/v1/admin',
            '/api/config', '/api/v1/config',
            '/api/settings', '/api/v1/settings',
            '/api/info', '/api/v1/info',
            '/api/version', '/api/v1/version',
            '/api/health', '/api/healthz', '/api/status', '/api/ping',
            '/api/products', '/api/v1/products',
            '/api/orders', '/api/v1/orders',
            '/api/items', '/api/v1/items',
            '/api/list', '/api/v1/list',
            '/api/search', '/api/v1/search',
            '/api/data', '/api/v1/data',
            '/api/export', '/api/v1/export',
            '/api/logs', '/api/v1/logs',
            '/api/metrics', '/api/v1/metrics',
            '/api/token', '/api/v1/token', '/api/auth', '/api/login',
            '/api/public', '/api/v1/public',
            '/graphql', '/graphiql', '/api/graphql', '/api/v1/graphql',
            '/v1/graphql', '/graphql/console',
            '/swagger.json', '/swagger/v1/swagger.json',
            '/api/swagger.json', '/api/v1/swagger.json',
            '/openapi.json', '/api/openapi.json', '/api/v1/openapi.json',
            '/api-docs', '/api-docs/', '/v2/api-docs', '/v3/api-docs',
            '/api/docs', '/docs', '/redoc',
            '/api/json', '/api/xml', '/api/rest', '/rest', '/rest/',
            '/rest/api', '/rest/api/', '/json', '/json/',
            '/api/file', '/api/files', '/api/download', '/api/upload',
            '/api/backup', '/api/export/csv', '/api/export/json',
            '/api/debug', '/api/test', '/api/internal',
            '/api/.env', '/api/config.json',
        ]

        open_apis = []

        def check(path):
            url = base + path
            try:
                r = subprocess.run(
                    ['curl', '-s', '-X', 'GET', '--max-time', '8',
                     '-H', 'Accept: application/json',
                     '-H', 'User-Agent: ' + self.best_ua,
                     '-w', '\n---HTTP_CODE:%{http_code}|SIZE:%{size_download}|CT:%{content_type}',
                     url],
                    capture_output=True, text=True, timeout=12)
                body = r.stdout
                if '---HTTP_CODE:' in body:
                    body, meta = body.rsplit('---HTTP_CODE:', 1)
                    code, rest = meta.split('|SIZE:', 1)
                    size, ct = rest.split('|CT:', 1)
                else:
                    code, size, ct = '0', '0', 'unknown'
                return path, code.strip(), size.strip(), ct.strip(), body.strip()
            except Exception:
                return path, 'ERR', '0', '', ''

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check, p): p for p in api_paths}
            for fut in as_completed(futures):
                path, code, size, ct, body = fut.result()
                if code == '200' and int(size or 0) > 0:
                    snippet = body[:200].replace('\n', ' ')
                    open_apis.append({
                        'path': path, 'code': code, 'size': size,
                        'ct': ct, 'snippet': snippet
                    })

        open_apis.sort(key=lambda x: x['path'])

        lines = []
        if geo_results:
            lines.append("=" * 60)
            lines.append("ГЕО-ДАННЫЕ IP (открытые сервисы, без ключа)")
            lines.append("=" * 60)
            for item in geo_results:
                lines.append(f"\n[{item['source']}] {item['url']}")
                lines.append(item['data'])
        elif is_ip:
            lines.append("[гео-сервисы не ответили или IP приватный]")

        lines.append("")
        lines.append("=" * 60)
        if open_apis:
            lines.append(f"ОТКРЫТЫХ API БЕЗ КЛЮЧА НА {real_host}: {len(open_apis)}")
            lines.append("=" * 60)
            for item in open_apis:
                lines.append("")
                lines.append(f"{item['code']}  {item['size']}b  {item['path']}")
                lines.append(f"      content-type: {item['ct']}")
                lines.append(f"      первые байты: {item['snippet']}")
        else:
            lines.append(f"[открытых API без авторизации на {real_host} не найдено]")
            lines.append("=" * 60)

        res = "\n".join(lines)
        self.save_output('apibrute', res)
        return res

    # ----- отчёты -----

    def save_summary(self, silent=False):
        txt_path = os.path.join(self.output_dir, 'SUMMARY.txt')
        with open(txt_path, 'w', errors='ignore') as f:
            f.write(f"{'='*60}\nCULTURE - ОТЧЁТ\n{'='*60}\n")
            f.write(f"Цель: {self.target}\n")
            f.write(f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"User-Agent: {self.best_ua}\n")
            f.write(f"{'='*60}\n\n")
            for name, data in self.results.items():
                f.write(f"[{name.upper()}] статус: {data['status']}\n")
                out = data['output'] or ''
                f.write(out + "\n")
                f.write(f"{'-'*60}\n\n")

        if self.use_json:
            json_path = os.path.join(self.output_dir, 'SUMMARY.json')
            with open(json_path, 'w', errors='ignore') as f:
                json.dump({
                    'target': self.target,
                    'time': datetime.now().isoformat(),
                    'user_agent': self.best_ua,
                    'results': self.results
                }, f, ensure_ascii=False, indent=2)
            if not silent:
                print(f"{Colors.GREEN}JSON: {json_path}{Colors.END}")

    def show_history(self):
        self.print_header()
        folders = sorted([d for d in os.listdir('.') if d.startswith('culture_') and os.path.isdir(d)], reverse=True)
        if not folders:
            print(f"{Colors.YELLOW}Нет сохранённых сканов{Colors.END}")
        else:
            for i, folder in enumerate(folders[:20], 1):
                print(f"  {Colors.GREEN}{i}.{Colors.END} {folder}")
        input(f"\n{Colors.CYAN}Enter...{Colors.END}")


def main():
    parser = argparse.ArgumentParser(description='Culture - авторазведка')
    parser.add_argument('--json', action='store_true', help='сохранять JSON отчёт')
    args = parser.parse_args()

    scanner = CultureScanner(use_json=args.json)
    scanner.check_tools()

    try:
        scanner.show_main_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Прервано{Colors.END}")
        sys.exit(0)


if __name__ == "__main__":
    main()