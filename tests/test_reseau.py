from sentinelle.modules.reseau.arp import parse_arp_output

# Faux résultat de "arp -a" : adresses inventées (le dépôt est public)
TEXTE_ARP = """
Interface: 10.0.0.7 --- 0xe
  Internet Address      Physical Address      Type
  10.0.0.1              aa-bb-cc-dd-ee-01     dynamic
  10.0.0.2              aa-bb-cc-dd-ee-02     dynamic
  10.0.63.255           ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
"""


def test_garde_seulement_les_vrais_appareils():
    appareils = parse_arp_output(TEXTE_ARP)
    assert len(appareils) == 2


def test_format_d_un_appareil():
    premier = parse_arp_output(TEXTE_ARP)[0]
    assert premier == {"ip": "10.0.0.1", "mac": "aa-bb-cc-dd-ee-01", "type": "dynamic"}


def test_texte_vide():
    assert parse_arp_output("") == []


def test_ligne_bizarre():
    assert parse_arp_output("n'importe quoi\n a b c \n") == []

from unittest.mock import patch
import subprocess

from sentinelle.modules.reseau.arp import lire_table_arp


def test_lire_table_arp_si_la_commande_n_existe_pas():
    with patch("sentinelle.modules.reseau.arp.subprocess.run", side_effect=FileNotFoundError):
        assert lire_table_arp() == []


def test_lire_table_arp_si_la_commande_est_trop_lente():
    with patch(
        "sentinelle.modules.reseau.arp.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="arp", timeout=5),
    ):
        assert lire_table_arp() == []