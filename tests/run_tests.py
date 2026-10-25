#!/usr/bin/env python3
"""Testes das regras e decoders do Reefed usando o wazuh-logtest.

Roda dentro do container do manager (ou em qualquer host com acesso ao socket
do logtest) e envia cada log de teste para o analysisd, comparando decoder,
regra, nível e campos extraídos com o que o caso de teste espera.

Uso típico (a partir da raiz do repositório):
    make test-rules

Ou manualmente:
    docker compose cp tests wazuh.manager:/tmp/reefed-tests
    docker compose exec wazuh.manager /var/ossec/framework/python/bin/python3 \
        /tmp/reefed-tests/run_tests.py --all-windows

Formato dos casos (tests/rules/*.yml):

    cases:
      - name: Login bem-sucedido no PostgreSQL
        when: business_hours
        log: '2026-10-22 13:10:14.904 UTC [75] user=app db=loja client=10.0.0.5 app=psql LOG:  connection authorized: ...'
        expect:
          decoder: reefed-postgresql
          rule: 110005
          level: 3
          fields:            # caminhos dentro de "data" do alerta
            dstuser: app
            db.name: loja
          mitre: [T1078]

      - name: Correlação (vários eventos na mesma sessão do logtest)
        steps:
          - log: '...falha...'
            repeat: 4
          - log: '...sucesso...'
            expect: {rule: 110203}

    Outras chaves por caso:
      when: em que janela de horário o caso vale (as regras de horário mudam o
            resultado de logins, comandos destrutivos, privilégios e exportações):
              business_hours  dentro do expediente e em dia útil
              in_hours        dentro do expediente (qualquer dia)
              off_hours       fora do horário (REEFED_OFF_HOURS)
              off_day         dia sem expediente (REEFED_OFF_DAYS), dentro do horário
      log_format: syslog (padrão) | json
      location: caminho do arquivo de origem (padrão: /var/log/reefed-test.log)
      expect.no_alert: true    o evento não pode gerar alerta
      expect.alert: true|false confere se o logtest marcou o evento como alerta
      expect.not_rule: 110210  regra (ou lista de regras) que não pode ser a final

Cada caso roda numa sessão nova do logtest, então contagens (frequency) de um
caso não vazam para outro.

O horário comercial é lido do arquivo de regras instalado no manager
(reefed-0900-horario_rules.xml). Sem opções, os casos com "when" que não valem
no horário atual são pulados. Com --all-windows o script troca temporariamente
as variáveis REEFED_OFF_HOURS/REEFED_OFF_DAYS desse arquivo (as sessões do
logtest leem as regras do disco), roda os casos de cada janela e restaura o
arquivo no final. O analysisd em produção só relê as regras quando reinicia.
"""

import argparse
import glob
import json
import os
import re
import socket
import struct
import sys
import time

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML não encontrado. Rode com /var/ossec/framework/python/bin/python3.")

DEFAULT_SOCKET = "/var/ossec/queue/sockets/logtest"
DEFAULT_LOCATION = "/var/log/reefed-test.log"
DEFAULT_HOURS_FILE = "/var/ossec/etc/rules/reefed-0900-horario_rules.xml"
DEFAULT_OFF_HOURS = "20:00 - 07:00"
DEFAULT_OFF_DAYS = "weekends"

DAY_NAMES = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"]
WINDOWS = ("business_hours", "in_hours", "off_hours", "off_day")


class Logtest:
    """Cliente mínimo do protocolo JSON do socket do wazuh-logtest."""

    def __init__(self, path):
        self.path = path

    def _call(self, command, parameters):
        message = {
            "version": 1,
            "origin": {"name": "reefed-tests", "module": "reefed"},
            "command": command,
            "parameters": parameters,
        }
        payload = json.dumps(message).encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.path)
            sock.sendall(struct.pack("<I", len(payload)) + payload)
            header = self._recv_exact(sock, 4)
            size = struct.unpack("<I", header)[0]
            response = json.loads(self._recv_exact(sock, size))
        if response.get("error", 0) != 0:
            raise RuntimeError(f"logtest respondeu erro: {response}")
        return response["data"]

    @staticmethod
    def _recv_exact(sock, size):
        chunks = b""
        while len(chunks) < size:
            chunk = sock.recv(size - len(chunks))
            if not chunk:
                raise RuntimeError("conexão com o logtest fechada")
            chunks += chunk
        return chunks

    def process(self, event, token=None, log_format="syslog", location=DEFAULT_LOCATION):
        params = {"event": event, "log_format": log_format, "location": location}
        if token:
            params["token"] = token
        return self._call("log_processing", params)

    def close(self, token):
        if token:
            try:
                self._call("remove_session", {"token": token})
            except RuntimeError:
                pass


# ---------------------------------------------------------------------------
# Horário comercial (mesma lógica do Wazuh para <time> e <weekday>)

def to_minutes(hhmm):
    hour, minute = hhmm.strip().split(":")
    return int(hour) * 60 + int(minute)


def from_minutes(minutes):
    minutes %= 24 * 60
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def in_window(window, minutes):
    """True se o minuto do dia cai na janela "HH:MM - HH:MM" (limites inclusos)."""
    start, end = [to_minutes(part) for part in window.split("-")]
    if start > end:  # atravessa a meia-noite: o Wazuh guarda como "fora de [fim, início]"
        return not (end <= minutes <= start)
    return start <= minutes <= end


def parse_days(spec):
    """Converte "weekends", "sat, sun", "!monday"... no conjunto de dias (0 = domingo)."""
    text = spec.strip().lower()
    negate = text.startswith("!")
    days = set()
    for word in re.split(r"[\s,]+", text.lstrip("!")):
        if not word:
            continue
        if word == "weekdays":
            days.update(range(1, 6))
        elif word == "weekends":
            days.update((0, 6))
        else:
            matches = [i for i, name in enumerate(DAY_NAMES) if word in (name, name[:3])]
            if not matches:
                raise ValueError(f"dia inválido em REEFED_OFF_DAYS: {word!r}")
            days.add(matches[0])
    return set(range(7)) - days if negate else days


def now_minutes_and_day():
    now = time.localtime()
    return now.tm_hour * 60 + now.tm_min, (now.tm_wday + 1) % 7  # tm_wday: 0 = segunda


def read_vars(path):
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    values = {}
    for name, default in (("REEFED_OFF_HOURS", DEFAULT_OFF_HOURS), ("REEFED_OFF_DAYS", DEFAULT_OFF_DAYS)):
        match = re.search(rf'<var name="{name}">([^<]*)</var>', text)
        values[name] = match.group(1) if match else default
    return text, values


def write_vars(path, original, off_hours, off_days):
    text = re.sub(r'(<var name="REEFED_OFF_HOURS">)[^<]*(</var>)', rf"\g<1>{off_hours}\g<2>", original)
    text = re.sub(r'(<var name="REEFED_OFF_DAYS">)[^<]*(</var>)', rf"\g<1>{off_days}\g<2>", text)
    with open(path, "w", encoding="utf-8") as handle:  # mesmo arquivo: mantém dono e permissões
        handle.write(text)


def current_windows(off_hours, off_days):
    minutes, day = now_minutes_and_day()
    is_off_hours = in_window(off_hours, minutes)
    is_off_day = day in parse_days(off_days)
    return {
        "business_hours": not is_off_hours and not is_off_day,
        "in_hours": not is_off_hours,
        "off_hours": is_off_hours,
        "off_day": is_off_day and not is_off_hours,
    }


def forced_settings(window):
    """Valores das variáveis que colocam o "agora" dentro da janela pedida."""
    minutes, day = now_minutes_and_day()
    today, tomorrow = DAY_NAMES[day], DAY_NAMES[(day + 1) % 7]
    later = f"{from_minutes(minutes + 60)} - {from_minutes(minutes + 120)}"
    around_now = f"{from_minutes(minutes - 60)} - {from_minutes(minutes + 60)}"
    return {
        "business_hours": (later, tomorrow),
        "off_hours": (around_now, tomorrow),
        "off_day": (later, today),
    }[window]


# ---------------------------------------------------------------------------
# Execução dos casos

def get_path(data, dotted):
    """Busca 'a.b.c' em dicionários aninhados (o Wazuh aninha campos com ponto)."""
    if dotted in data:
        return data[dotted]
    current = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def check(expect, output, alert):
    """Retorna a lista de divergências entre o esperado e a saída do logtest."""
    problems = []
    rule = output.get("rule", {})
    decoder = output.get("decoder", {})
    data = output.get("data", {})

    if "not_rule" in expect:
        banned = expect["not_rule"] if isinstance(expect["not_rule"], list) else [expect["not_rule"]]
        if str(rule.get("id")) in {str(item) for item in banned}:
            problems.append(f"a regra {rule.get('id')} não devia disparar ({rule.get('description')})")

    if expect.get("no_alert"):
        if alert:
            problems.append(f"não devia alertar, mas gerou a regra {rule.get('id')} "
                            f"(nível {rule.get('level')}): {rule.get('description')}")
        if "rule" in expect and str(rule.get("id")) != str(expect["rule"]):
            problems.append(f"regra esperada {expect['rule']}, obtida {rule.get('id')}")
        return problems

    if "decoder" in expect and decoder.get("name") != expect["decoder"]:
        problems.append(f"decoder esperado {expect['decoder']}, obtido {decoder.get('name')}")
    if "rule" in expect and str(rule.get("id")) != str(expect["rule"]):
        problems.append(f"regra esperada {expect['rule']}, obtida {rule.get('id')} "
                        f"(nível {rule.get('level')}: {rule.get('description')})")
    if "level" in expect and int(rule.get("level", -1)) != int(expect["level"]):
        problems.append(f"nível esperado {expect['level']}, obtido {rule.get('level')}")
    if "alert" in expect and bool(alert) != bool(expect["alert"]):
        problems.append(f"alerta esperado: {expect['alert']}, obtido: {bool(alert)}")
    for name, value in (expect.get("fields") or {}).items():
        got = get_path(data, name)
        if str(got) != str(value):
            problems.append(f"campo {name}: esperado {value!r}, obtido {got!r}")
    for name in expect.get("absent_fields") or []:
        got = get_path(data, name)
        if got is not None:
            problems.append(f"campo {name} devia estar ausente, obtido {got!r}")
    if "mitre" in expect:
        got = set(rule.get("mitre", {}).get("id", []))
        missing = set(expect["mitre"]) - got
        if missing:
            problems.append(f"MITRE esperado {sorted(expect['mitre'])}, obtido {sorted(got)}")
    for group in expect.get("groups") or []:
        if group not in rule.get("groups", []):
            problems.append(f"grupo {group} ausente em {rule.get('groups')}")
    return problems


def run_case(client, case, verbose=False):
    steps = case.get("steps") or [case]
    token = None
    problems = []
    last_output = None
    try:
        for index, step in enumerate(steps, 1):
            repeat = int(step.get("repeat", 1))
            log_format = step.get("log_format", case.get("log_format", "syslog"))
            location = step.get("location", case.get("location", DEFAULT_LOCATION))
            event = step["log"]
            if not isinstance(event, str):
                event = json.dumps(event, ensure_ascii=False)
            for _ in range(repeat):
                result = client.process(event, token, log_format, location)
                token = result.get("token", token)
            last_output = result.get("output", {})
            if "expect" in step:
                for problem in check(step["expect"], last_output, result.get("alert", False)):
                    prefix = f"passo {index}: " if len(steps) > 1 else ""
                    problems.append(prefix + problem)
    finally:
        client.close(token)
    if problems and verbose and last_output is not None:
        problems.append("saída: " + json.dumps(last_output, ensure_ascii=False, indent=2))
    return problems


def load_suites(paths, name_filter):
    suites = []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            suite = yaml.safe_load(handle) or {}
        cases = []
        for case in suite.get("cases", []):
            if name_filter and name_filter.lower() not in case.get("name", "").lower():
                continue
            when = case.get("when")
            if when is not None and when not in WINDOWS:
                sys.exit(f"{path}: caso {case.get('name')!r} com when inválido: {when!r}")
            cases.append(case)
        suites.append((suite.get("name", os.path.basename(path)), os.path.basename(path), cases))
    return suites


def run_suites(client, suites, selector, verbose):
    passed = failed = 0
    for title, filename, cases in suites:
        chosen = [case for case in cases if selector(case)]
        if not chosen:
            continue
        print(f"\n== {title} ({filename})")
        for case in chosen:
            name = case.get("name", "sem nome")
            if case.get("when"):
                name += f" [{case['when']}]"
            try:
                problems = run_case(client, case, verbose)
            except (OSError, RuntimeError) as exc:
                problems = [f"erro ao falar com o logtest: {exc}"]
            if problems:
                failed += 1
                print(f"  FAIL  {name}")
                for problem in problems:
                    print(f"        - {problem}")
            else:
                passed += 1
                print(f"  ok    {name}")
    return passed, failed


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Testes de regras do Reefed (wazuh-logtest)")
    parser.add_argument("paths", nargs="*", help="arquivos .yml (padrão: tests/rules/*.yml)")
    parser.add_argument("--socket", default=DEFAULT_SOCKET, help="socket do logtest")
    parser.add_argument("--filter", "-k", default="", help="roda só casos cujo nome contém este texto")
    parser.add_argument("--hours-file", default=DEFAULT_HOURS_FILE,
                        help="arquivo de regras com REEFED_OFF_HOURS/REEFED_OFF_DAYS instalado no manager")
    parser.add_argument("--all-windows", action="store_true",
                        help="roda também os casos de outras janelas de horário (altera e restaura o arquivo de horário)")
    parser.add_argument("-v", "--verbose", action="store_true", help="mostra a saída completa nas falhas")
    args = parser.parse_args()

    files = args.paths or sorted(glob.glob(os.path.join(here, "rules", "*.yml")))
    if not files:
        sys.exit("Nenhum arquivo de teste encontrado.")
    suites = load_suites(files, args.filter)
    client = Logtest(args.socket)

    try:
        original, values = read_vars(args.hours_file)
    except OSError as exc:
        if args.all_windows:
            sys.exit(f"Não consegui ler {args.hours_file}: {exc}")
        original, values = None, {"REEFED_OFF_HOURS": DEFAULT_OFF_HOURS, "REEFED_OFF_DAYS": DEFAULT_OFF_DAYS}

    passed = failed = skipped = 0
    if not args.all_windows:
        windows = current_windows(values["REEFED_OFF_HOURS"], values["REEFED_OFF_DAYS"])
        active = [name for name, on in windows.items() if on]
        print(f"Horário fora do expediente: {values['REEFED_OFF_HOURS']} / dias: {values['REEFED_OFF_DAYS']} "
              f"(agora: {', '.join(active)})")
        selector = lambda case: not case.get("when") or windows[case["when"]]
        p, f = run_suites(client, suites, selector, args.verbose)
        passed, failed = p, f
        skipped = sum(1 for _, _, cases in suites for case in cases if not selector(case))
    else:
        try:
            for index, window in enumerate(("business_hours", "off_hours", "off_day")):
                off_hours, off_days = forced_settings(window)
                write_vars(args.hours_file, original, off_hours, off_days)
                windows = current_windows(off_hours, off_days)
                if not windows[window]:
                    sys.exit(f"Falha interna: a janela {window} não ficou ativa ({off_hours} / {off_days}).")
                print(f"\n##### Janela {window}: REEFED_OFF_HOURS={off_hours}, REEFED_OFF_DAYS={off_days}")

                def selector(case, index=index, windows=windows):
                    when = case.get("when")
                    if not when:
                        return index == 0  # casos sem horário rodam uma vez só
                    return windows[when] and (when == window or (when == "in_hours" and index == 0))

                p, f = run_suites(client, suites, selector, args.verbose)
                passed += p
                failed += f
        finally:
            with open(args.hours_file, "w", encoding="utf-8") as handle:
                handle.write(original)

    print(f"\nResultado: {passed} ok, {failed} falha(s), {skipped} pulado(s)")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
