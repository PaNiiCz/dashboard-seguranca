from scapy.all import ARP, Ether, srp
import sys


def scan_rede(faixa_ip):
    """
    Envia requisições ARP para todos os IPs da faixa informada
    e retorna a lista de dispositivos que responderam.
    """
    pacote_arp = ARP(pdst=faixa_ip)
    pacote_ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pacote_completo = pacote_ether / pacote_arp

    respostas = srp(pacote_completo, timeout=2, verbose=False)[0]

    dispositivos = []
    for enviado, recebido in respostas:
        dispositivos.append({
            "ip": recebido.psrc,
            "mac": recebido.hwsrc,
        })

    return dispositivos


if __name__ == "__main__":
    faixa = "192.168.0.0/24"
    print(f"Escaneando a rede {faixa}...\n")

    dispositivos = scan_rede(faixa)

    if not dispositivos:
        print("Nenhum dispositivo encontrado. Verifique se está rodando o terminal como Administrador.")
        sys.exit(1)

    print(f"{'IP':<18}{'MAC'}")
    print("-" * 40)
    for d in dispositivos:
        print(f"{d['ip']:<18}{d['mac']}")
