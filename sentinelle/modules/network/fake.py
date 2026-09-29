"""Appareils SIMULÉS pour développer l'interface sans vrai réseau.

1er scan : 4 appareils "de la maison". 2e scan et suivants : un appareil inconnu apparaît.
"""
from ...models import Device

_calls = {"n": 0}


def scan() -> list[Device]:
    _calls["n"] += 1
    devices = [
        Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.1", hostname="box-internet", vendor="Routeur"),
        Device(mac="aa:bb:cc:00:00:02", ip="192.168.1.20", hostname="pc-bureau", vendor="Ordinateur"),
        Device(mac="aa:bb:cc:00:00:03", ip="192.168.1.21", hostname="telephone", vendor="Téléphone"),
        Device(mac="aa:bb:cc:00:00:04", ip="192.168.1.30", hostname="tv-salon", vendor="Télévision"),
    ]
    if _calls["n"] >= 2:
        devices.append(Device(mac="de:ad:be:ef:00:99", ip="192.168.1.77", hostname="", vendor="Inconnu"))
    return devices


def reset() -> None:
    _calls["n"] = 0
