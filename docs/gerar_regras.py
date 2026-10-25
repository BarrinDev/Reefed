#!/usr/bin/env python3
"""Gera o catálogo de regras do docs/regras.md a partir de wazuh/rules/*.xml.

O trecho entre os marcadores REGRAS:INICIO e REGRAS:FIM é reescrito; o resto do
docs/regras.md é texto normal. O CI roda com --check para avisar quando alguém
muda uma regra e esquece de atualizar a documentação.

    python3 docs/gerar_regras.py           # atualiza docs/regras.md
    python3 docs/gerar_regras.py --check   # só confere (código 1 se estiver desatualizado)
"""

import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "regras.md")
BEGIN = "<!-- REGRAS:INICIO (gerado por docs/gerar_regras.py; não edite à mão) -->"
END = "<!-- REGRAS:FIM -->"

# Nome e táticas das técnicas usadas pelo Reefed (MITRE ATT&CK Enterprise)
TECHNIQUES = {
    "T1005": ("Data from Local System", ["Collection"]),
    "T1027": ("Obfuscated Files or Information", ["Defense Evasion"]),
    "T1030": ("Data Transfer Size Limits", ["Exfiltration"]),
    "T1046": ("Network Service Discovery", ["Discovery"]),
    "T1059": ("Command and Scripting Interpreter", ["Execution"]),
    "T1059.004": ("Unix Shell", ["Execution"]),
    "T1068": ("Exploitation for Privilege Escalation", ["Privilege Escalation"]),
    "T1069": ("Permission Groups Discovery", ["Discovery"]),
    "T1070": ("Indicator Removal", ["Defense Evasion"]),
    "T1070.004": ("File Deletion", ["Defense Evasion"]),
    "T1074.001": ("Local Data Staging", ["Collection"]),
    "T1078": ("Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1078.001": ("Default Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1083": ("File and Directory Discovery", ["Discovery"]),
    "T1087": ("Account Discovery", ["Discovery"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Password Guessing", ["Credential Access"]),
    "T1110.003": ("Password Spraying", ["Credential Access"]),
    "T1119": ("Automated Collection", ["Collection"]),
    "T1136": ("Create Account", ["Persistence"]),
    "T1190": ("Exploit Public-Facing Application", ["Initial Access"]),
    "T1213": ("Data from Information Repositories", ["Collection"]),
    "T1485": ("Data Destruction", ["Impact"]),
    "T1489": ("Service Stop", ["Impact"]),
    "T1499": ("Endpoint Denial of Service", ["Impact"]),
    "T1505": ("Server Software Component", ["Persistence"]),
    "T1505.001": ("SQL Stored Procedures", ["Persistence"]),
    "T1531": ("Account Access Removal", ["Impact"]),
    "T1552.004": ("Private Keys", ["Credential Access"]),
    "T1555": ("Credentials from Password Stores", ["Credential Access"]),
    "T1556": ("Modify Authentication Process", ["Credential Access", "Defense Evasion", "Persistence"]),
    "T1562.001": ("Disable or Modify Tools", ["Defense Evasion"]),
    "T1565.001": ("Stored Data Manipulation", ["Impact"]),
}

# Ordem da matriz do ATT&CK, com o nome em português
TACTICS = [
    ("Initial Access", "Acesso inicial"),
    ("Execution", "Execução"),
    ("Persistence", "Persistência"),
    ("Privilege Escalation", "Escalada de privilégio"),
    ("Defense Evasion", "Evasão de defesas"),
    ("Credential Access", "Acesso a credenciais"),
    ("Discovery", "Descoberta"),
    ("Collection", "Coleta"),
    ("Exfiltration", "Exfiltração"),
    ("Impact", "Impacto"),
]


def severity(level):
    if level >= 12:
        return "crítico"
    if level >= 10:
        return "alto"
    if level >= 7:
        return "médio"
    return "baixo"


def describe(text):
    text = re.sub(r"^Reefed:\s*", "", " ".join(text.split()))
    first = text.split(" ", 1)[0]
    if text and "-" not in first and not first.startswith("$("):   # "skip-grant-tables" fica como está
        text = text[0].upper() + text[1:]
    text = re.sub(r"\$\(([\w.]+)\)", r"`\1`", text)
    return text.replace("|", "\\|")


def load():
    sections = []
    for path in sorted(glob.glob(os.path.join(ROOT, "wazuh", "rules", "*.xml"))):
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        header = re.search(r"<!--\s*\n?\s*Reefed - (.+)", text)
        title = header.group(1).strip() if header else os.path.basename(path)
        title = re.sub(r"\s*\(IDs [^)]*\)\s*$", "", title)
        rules = []
        for rule in ET.fromstring(f"<r>{text}</r>").iter("rule"):
            rules.append({
                "id": rule.get("id"),
                "level": int(rule.get("level")),
                "description": (rule.findtext("description") or "").strip(),
                "mitre": [item.text.strip() for item in rule.iter("id")],
            })
        sections.append((title[0].upper() + title[1:], os.path.basename(path), rules))
    return sections


def render(sections):
    lines = [BEGIN, ""]
    alerting = [rule for _, _, rules in sections for rule in rules if rule["level"] > 0]
    base = sum(1 for _, _, rules in sections for rule in rules if rule["level"] == 0)
    lines.append(f"{len(alerting)} regras que geram alerta, em {len(sections)} arquivos "
                 f"(mais {base} regras de nível 0, que só agrupam eventos para as outras).")
    lines.append("")
    for title, filename, rules in sections:
        shown = sorted((rule for rule in rules if rule["level"] > 0), key=lambda rule: int(rule["id"]))
        if not shown:
            continue
        lines += [f"### {title}", "", f"Arquivo: `wazuh/rules/{filename}`", "",
                  "| ID | Nível | Alerta | MITRE ATT&CK |", "|---|---|---|---|"]
        for rule in shown:
            mitre = ", ".join(rule["mitre"]) or "-"
            lines.append(f"| {rule['id']} | {rule['level']} ({severity(rule['level'])}) | "
                         f"{describe(rule['description'])} | {mitre} |")
        lines.append("")

    unknown = sorted({tid for rule in alerting for tid in rule["mitre"]} - set(TECHNIQUES))
    if unknown:
        raise SystemExit(f"técnicas sem nome em TECHNIQUES: {', '.join(unknown)}")

    lines += ["### Cobertura MITRE ATT&CK", "",
              "Cada técnica aparece em todas as táticas a que pertence no ATT&CK.", "",
              "| Tática | Técnica | Regras |", "|---|---|---|"]
    for tactic, portuguese in TACTICS:
        for tid in sorted(TECHNIQUES, key=lambda t: [int(p) for p in t[1:].split(".")]):
            name, tactics = TECHNIQUES[tid]
            if tactic not in tactics:
                continue
            ids = [rule["id"] for rule in alerting if tid in rule["mitre"]]
            if ids:
                lines.append(f"| {portuguese} ({tactic}) | {tid} {name} | {', '.join(sorted(ids))} |")
    lines += ["", END]
    return "\n".join(lines)


def main():
    with open(DOC, encoding="utf-8") as handle:
        current = handle.read()
    if BEGIN not in current or END not in current:
        raise SystemExit(f"marcadores não encontrados em {DOC}")
    before = current[:current.index(BEGIN)]
    after = current[current.index(END) + len(END):]
    updated = before + render(load()) + after
    if "--check" in sys.argv:
        if updated != current:
            print("docs/regras.md está desatualizado: rode python3 docs/gerar_regras.py")
            return 1
        print("docs/regras.md em dia com as regras")
        return 0
    if updated != current:
        with open(DOC, "w", encoding="utf-8") as handle:
            handle.write(updated)
        print("docs/regras.md atualizado")
    else:
        print("docs/regras.md já estava em dia")
    return 0


if __name__ == "__main__":
    sys.exit(main())
