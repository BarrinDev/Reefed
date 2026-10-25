"""Deixa o pacote app (api/app) importável de qualquer pasta: o make test e o CI rodam
o pytest a partir da raiz do repositório."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
