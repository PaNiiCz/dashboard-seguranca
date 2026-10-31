import subprocess
import re
import sys
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from scapy.all import conf

# Evita abrir janelinhas de console quando rodar dentro da interface gráfica
SEM_JANELA = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def pingar(ip):
    """
    Faz um ping rápido (1 pacote, timeout curto) usando o comando
    nativo do Windows. Retorna True se o IP respondeu.
    """
    resultado = subprocess.run(
        ["ping", "-n", "1", "-w", "300", str(ip)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=SEM_JANELA,
    )
    return resultado.returncode == 0


def ping_sweep(faixa_cidr):
    """
    Faz ping em paralelo em todos os IPs da faixa, para preencher
    a tabela ARP do Windows com os dispositivos ativos.
    """
    rede = ipaddress.ip_network(faixa_cidr, strict=False)
    ips = [str(ip) for ip in rede.hosts()]

    with ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(pingar, ips))


def ler_tabela_arp(faixa_cidr):
    """
    Lê a tabela ARP do Windows (arp -a) e extrai pares IP/MAC,
    mantendo só os IPs que pertencem à faixa escaneada.
    """
    rede = ipaddress.ip_network(faixa_cidr, strict=False)

    saida = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True,
        encoding="cp850",
        errors="replace",
        creationflags=SEM_JANELA,
    ).stdout

    padrao = re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
        r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-"
        r"[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})\s+din"
    )

    dispositivos = []
    for linha in saida.splitlines():
        m = padrao.search(linha)
        if m:
            ip, mac = m.group(1), m.group(2).replace("-", ":")
            if ipaddress.ip_address(ip) in rede:
                dispositivos.append({"ip": ip, "mac": mac})

    return dispositivos


def pegar_fabricante(mac):
    try:
        return conf.manufdb._get_manuf(mac)
    except Exception:
        return "Desconhecido"


def ip_deste_pc():
    """
    Descobre o IP local deste computador. O 'connect' em UDP não envia
    nada pela rede, só faz o Windows escolher a interface de saída.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def medir_latencia(ip, tentativas=3):
    """
    Faz alguns pings e devolve (latencia_media_ms, perda_percentual).
    Se ninguém respondeu, a latência vem como None.
    """
    saida = subprocess.run(
        ["ping", "-n", str(tentativas), "-w", "500", str(ip)],
        capture_output=True,
        text=True,
        encoding="cp850",
        errors="replace",
        creationflags=SEM_JANELA,
    ).stdout

    # Funciona no Windows em português ("tempo=12ms") e inglês ("time=12ms")
    tempos = [
        int(t)
        for t in re.findall(r"(?:tempo|time)\s*[=<]\s*(\d+)\s*ms", saida, re.IGNORECASE)
    ]

    perda = (tentativas - len(tempos)) / tentativas * 100
    media = sum(tempos) / len(tempos) if tempos else None
    return media, perda


def classificar_status(media, perda):
    if media is None:
        return "offline"
    if perda >= 50 or media >= 150:
        return "ruim"
    if perda > 0 or media >= 50:
        return "atenção"
    return "saudável"


def _analisar(dispositivo):
    media, perda = medir_latencia(dispositivo["ip"])
    dispositivo["latencia_ms"] = media
    dispositivo["perda_pct"] = perda
    dispositivo["status"] = classificar_status(media, perda)
    return dispositivo


def escanear(faixa_cidr):
    """
    Função principal do módulo (a interface vai chamar esta).
    Devolve uma lista de dicionários com: ip, mac, fabricante,
    latencia_ms, perda_pct e status.
    """
    ping_sweep(faixa_cidr)
    dispositivos = ler_tabela_arp(faixa_cidr)

    # O arp -a nunca lista o próprio PC, então adicionamos manualmente
    meu_ip = ip_deste_pc()
    rede = ipaddress.ip_network(faixa_cidr, strict=False)
    if meu_ip and ipaddress.ip_address(meu_ip) in rede:
        if all(d["ip"] != meu_ip for d in dispositivos):
            dispositivos.append({"ip": meu_ip, "mac": "—", "este_pc": True})

    for d in dispositivos:
        if d["mac"] != "—":
            d["fabricante"] = pegar_fabricante(d["mac"])
        else:
            d["fabricante"] = "(este PC)"

    with ThreadPoolExecutor(max_workers=20) as executor:
        dispositivos = list(executor.map(_analisar, dispositivos))

    dispositivos.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return dispositivos


if __name__ == "__main__":
    faixa = "192.168.0.0/24"
    print(f"Escaneando a rede {faixa} (ping sweep + latência)...\n")

    dispositivos = escanear(faixa)

    if not dispositivos:
        print("Nenhum dispositivo encontrado.")
        sys.exit(1)

    print(f"{'IP':<16}{'MAC':<19}{'Fabricante':<30}{'Latência':<11}{'Perda':<8}{'Status'}")
    print("-" * 95)
    for d in dispositivos:
        lat = f"{d['latencia_ms']:.0f} ms" if d["latencia_ms"] is not None else "—"
        perda = f"{d['perda_pct']:.0f}%"
        print(
            f"{d['ip']:<16}{d['mac']:<19}{d['fabricante'][:28]:<30}"
            f"{lat:<11}{perda:<8}{d['status']}"
        )