#!/usr/bin/env python3
"""Confere os arquivos XML do Reefed sem precisar do Wazuh (roda no CI).

- regras, decoders, agent.conf e o modelo do ossec.conf são XML bem formado;
- ids de regra são únicos e ficam na faixa do Reefed (110000-119999);
- toda regra tem descrição e as técnicas MITRE têm o formato T1234 ou T1234.001;
- if_sid / if_matched_sid apontam para regras do Reefed que existem (ids abaixo
  de 100000 são do Wazuh e não são conferidos aqui);
- nenhum <command> usa "&" (o Wazuh não decodifica entidades XML antes de executar).

Uso: python3 tests/lint_xml.py   (código de saída 1 se achar problema)
"""

import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse(path):
    """Os arquivos do Wazuh podem ter vários elementos na raiz: embrulha num só."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    return ET.fromstring(f"<reefed-lint>{text}</reefed-lint>")


def main():
    problems = []
    files = {
        "rules": sorted(glob.glob(os.path.join(ROOT, "wazuh/rules/*.xml"))),
        "decoders": sorted(glob.glob(os.path.join(ROOT, "wazuh/decoders/*.xml"))),
        "shared": sorted(glob.glob(os.path.join(ROOT, "wazuh/shared/*/agent.conf"))),
        "config": [os.path.join(ROOT, "config/wazuh_manager/ossec.conf")],
    }
    trees = {}
    for kind, paths in files.items():
        if not paths:
            problems.append(f"nenhum arquivo de {kind} encontrado")
        for path in paths:
            try:
                trees[path] = parse(path)
            except ET.ParseError as exc:
                problems.append(f"{os.path.relpath(path, ROOT)}: XML inválido: {exc}")

    rules = {}
    for path in files["rules"]:
        tree = trees.get(path)
        if tree is None:
            continue
        for rule in tree.iter("rule"):
            rid = rule.get("id", "")
            where = f"{os.path.relpath(path, ROOT)} regra {rid}"
            if not rid.isdigit() or not 110000 <= int(rid) <= 119999:
                problems.append(f"{where}: id fora da faixa do Reefed (110000-119999)")
            if rid in rules:
                problems.append(f"{where}: id repetido (também em {rules[rid][0]})")
            rules[rid] = (os.path.relpath(path, ROOT), rule)
            level = rule.get("level", "")
            if not level.isdigit() or int(level) > 16:
                problems.append(f"{where}: nível inválido '{level}'")
            if not (rule.findtext("description") or "").strip():
                problems.append(f"{where}: sem descrição")
            for technique in rule.iter("id"):
                if not re.fullmatch(r"T\d{4}(\.\d{3})?", (technique.text or "").strip()):
                    problems.append(f"{where}: técnica MITRE com formato inválido '{technique.text}'")

    for rid, (path, rule) in rules.items():
        for tag in ("if_sid", "if_matched_sid"):
            for element in rule.iter(tag):
                for ref in re.split(r"[,\s]+", (element.text or "").strip()):
                    if ref and ref.isdigit() and int(ref) >= 100000 and ref not in rules:
                        problems.append(f"{path} regra {rid}: {tag} {ref} não existe")

    for path, tree in trees.items():
        for command in tree.iter("command"):
            if "&" in (command.text or ""):
                problems.append(f"{os.path.relpath(path, ROOT)}: <command> com '&' (use if/then/else)")

    total = sum(len(paths) for paths in files.values())
    if problems:
        print("\n".join(problems))
        print(f"\n{len(problems)} problema(s) em {total} arquivos")
        return 1
    print(f"XML ok: {total} arquivos, {len(rules)} regras do Reefed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
