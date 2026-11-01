"""verificacao.py - verifica portas comuns dos aparelhos da MINHA rede.

Só tenta conectar (não explora nada). Use apenas na sua própria rede.
Uso:  python verificacao.py            (varre 192.168.0.1 a 192.168.0.254)
      python verificacao.py --rede 192.168.1
      python verificacao.py --ip 192.168.0.1
"""
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

# porta: (serviço, risco, observação)
PORTAS = {
    21: ("FTP", "médio", "transferência sem criptografia"),
    22: ("SSH", "baixo", "acesso remoto (normal em Linux/NAS)"),
    23: ("Telnet", "ALTO", "acesso remoto sem criptografia, deveria estar fechado"),
    53: ("DNS", "baixo", "normal em roteador"),
    80: ("HTTP", "baixo", "página web / painel de administração"),
    139: ("NetBIOS", "médio", "compartilhamento Windows antigo"),
    443: ("HTTPS", "baixo", "página web segura / painel"),
    445: ("SMB", "médio", "compartilhamento de arquivos Windows"),
    554: ("RTSP", "médio", "vídeo de câmera"),
    3389: ("RDP", "médio", "área de trabalho remota do Windows"),
    5900: ("VNC", "médio", "controle remoto de tela"),
    7547: ("TR-069", "médio", "gerência remota da operadora (comum em modem)"),
    8008: ("Cast", "baixo", "Chromecast / TV Google"),
    8009: ("Cast", "baixo", "Chromecast / TV Google"),
    8080: ("HTTP-alt", "baixo", "página web alternativa"),
    8443: ("HTTPS-alt", "baixo", "página web segura alternativa"),
    9100: ("Impressora", "baixo", "impressão de rede"),
    62078: ("iPhone", "baixo", "serviço interno de iPhone/iPad"),
}


def porta_aberta(ip, porta, timeout=0.5):
    try:
        with socket.create_connection((ip, porta), timeout=timeout):
            return True
    except OSError:
        return False


def palpite_tipo(portas):
    if 62078 in portas:
        return "Provável iPhone/iPad"
    if 8008 in portas or 8009 in portas:
        return "Provável Chromecast / TV Google"
    if 9100 in portas:
        return "Provável impressora"
    if 554 in portas:
        return "Provável câmera / DVR"
    if 3389 in portas or 445 in portas or 139 in portas:
        return "Provável PC Windows ou NAS"
    if 80 in portas or 443 in portas:
        return "Aparelho com página web (roteador, TV, IoT)"
    return "Sem pistas (comum em celulares)"


def verificar(ips):
    tarefas = [(ip, p) for ip in ips for p in PORTAS]
    abertas = {}
    with ThreadPoolExecutor(max_workers=200) as pool:
        resultados = pool.map(lambda t: (t, porta_aberta(*t)), tarefas)
        for (ip, porta), aberta in resultados:
            if aberta:
                abertas.setdefault(ip, []).append(porta)
    return abertas


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rede", default="192.168.0", help="prefixo, ex: 192.168.0")
    ap.add_argument("--ip", help="verificar só um IP")
    args = ap.parse_args()

    ips = [args.ip] if args.ip else [f"{args.rede}.{i}" for i in range(1, 255)]
    print(f"Verificando {len(ips)} endereço(s) (só na sua rede)... aguarde.\n")
    abertas = verificar(ips)

    if not abertas:
        print("Nenhuma das portas comuns está aberta nos aparelhos verificados.")
        return
    for ip in sorted(abertas, key=lambda x: tuple(int(n) for n in x.split("."))):
        portas = sorted(abertas[ip])
        print(f"{ip}  ->  {palpite_tipo(portas)}")
        for p in portas:
            servico, risco, obs = PORTAS[p]
            print(f"    porta {p:<5} {servico:<10} risco {risco:<6} {obs}")
        print()


if __name__ == "__main__":
    main()