import subprocess
import re
import sys
import json
import socket
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from scapy.all import conf

# Evita abrir janelinhas de console quando rodar dentro da interface gráfica
SEM_JANELA = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Inventário dos aparelhos que você conhece: { "mac": "nome do aparelho" }
ARQUIVO_CONHECIDOS = Path(__file__).resolve().parent / "dispositivos_conhecidos.json"


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
    Os MACs são guardados sempre em minúsculas.
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
            ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
            if ipaddress.ip_address(ip) in rede:
                dispositivos.append({"ip": ip, "mac": mac})

    return dispositivos


def mac_privado(mac):
    """
    MAC 'privado/aleatório' (usado por celulares com endereço Wi-Fi
    privado): o bit de 'administrado localmente' está ligado, ou seja,
    o segundo dígito hexadecimal do MAC é 2, 6, A ou E.
    """
    primeiro_byte = int(mac.split(":")[0], 16)
    return bool(primeiro_byte & 0b10)


def pegar_fabricante(mac):
    if mac_privado(mac):
        return "MAC privado (aleatório)"
    try:
        fabricante = conf.manufdb._get_manuf(mac)
    except Exception:
        return "Desconhecido"
    # Quando não encontra, o Scapy devolve o próprio MAC
    if not fabricante or fabricante.lower() == mac.lower():
        return "Desconhecido"
    return fabricante


def ip_deste_pc(faixa_cidr):
    """
    Descobre o IP deste computador DENTRO da faixa escaneada.
    O 'connect' em UDP não envia nada pela rede: só faz o Windows
    escolher a placa que alcança aquela faixa e nos dizer o IP dela.
    """
    rede = ipaddress.ip_network(faixa_cidr, strict=False)
    alvo = str(next(rede.hosts()))

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((alvo, 80))
        ip = s.getsockname()[0]
        return ip if ipaddress.ip_address(ip) in rede else None
    except OSError:
        return None
    finally:
        s.close()


def nome_na_rede(ip):
    """
    Tenta descobrir o nome do aparelho (ex: 'Galaxy-A54') perguntando
    ao DNS da rede. Muitos roteadores respondem com o nome que o
    aparelho informou ao entrar no Wi-Fi. Se não souber, devolve None.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


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
    if perda >= 50 or media >= 250:
        return "ruim"
    if perda > 0 or media >= 100:
        return "atenção"
    return "saudável"


def carregar_conhecidos():
    """
    Lê o inventário de aparelhos conhecidos: { "mac": "nome" }.
    Se o arquivo ainda não existe, devolve um inventário vazio.
    """
    try:
        with open(ARQUIVO_CONHECIDOS, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
        return {mac.lower(): nome for mac, nome in dados.items()}
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, AttributeError):
        print(f"Aviso: o arquivo {ARQUIVO_CONHECIDOS.name} está com erro de formato; ignorando.")
        return {}


def salvar_conhecidos(conhecidos):
    with open(ARQUIVO_CONHECIDOS, "w", encoding="utf-8") as arquivo:
        json.dump(conhecidos, arquivo, indent=2, ensure_ascii=False)


def _analisar(dispositivo):
    media, perda = medir_latencia(dispositivo["ip"])
    dispositivo["latencia_ms"] = media
    dispositivo["perda_pct"] = perda
    dispositivo["status"] = classificar_status(media, perda)
    dispositivo["nome_rede"] = nome_na_rede(dispositivo["ip"])
    return dispositivo


def escanear(faixa_cidr):
    """
    Função principal do módulo (a interface vai chamar esta).
    Devolve uma lista de dicionários com: ip, mac, fabricante, nome,
    conhecido, nome_rede, latencia_ms, perda_pct, status e (opcional) este_pc.
    """
    ping_sweep(faixa_cidr)
    dispositivos = ler_tabela_arp(faixa_cidr)

    # O arp -a normalmente não lista o próprio PC, então garantimos aqui
    meu_ip = ip_deste_pc(faixa_cidr)
    if meu_ip:
        existente = next((d for d in dispositivos if d["ip"] == meu_ip), None)
        if existente:
            existente["este_pc"] = True
        else:
            dispositivos.append({"ip": meu_ip, "mac": "—", "este_pc": True})

    conhecidos = carregar_conhecidos()
    for d in dispositivos:
        if d.get("este_pc"):
            d["fabricante"] = "(este PC)"
            d["nome"] = "(este PC)"
            d["conhecido"] = True
        else:
            d["fabricante"] = pegar_fabricante(d["mac"])
            d["nome"] = conhecidos.get(d["mac"])
            d["conhecido"] = d["nome"] is not None

    with ThreadPoolExecutor(max_workers=20) as executor:
        dispositivos = list(executor.map(_analisar, dispositivos))

    dispositivos.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return dispositivos


def imprimir_tabela(dispositivos):
    print(
        f"{'IP':<15}{'MAC':<18}{'Identificação':<22}{'Fabricante':<26}"
        f"{'Nome na rede':<20}{'Latência':<10}{'Perda':<7}{'Status'}"
    )
    print("-" * 125)
    for d in dispositivos:
        identificacao = d["nome"] if d["conhecido"] else "[!] DESCONHECIDO"
        lat = f"{d['latencia_ms']:.0f} ms" if d["latencia_ms"] is not None else "—"
        perda = f"{d['perda_pct']:.0f}%"
        nome_rede = d["nome_rede"] or "—"
        print(
            f"{d['ip']:<15}{d['mac']:<18}{identificacao[:20]:<22}"
            f"{d['fabricante'][:24]:<26}{nome_rede[:18]:<20}"
            f"{lat:<10}{perda:<7}{d['status']}"
        )

    total = len(dispositivos)
    desconhecidos = [d for d in dispositivos if not d["conhecido"]]
    print(
        f"\nTotal: {total} | Conhecidos: {total - len(desconhecidos)} "
        f"| Desconhecidos: {len(desconhecidos)}"
    )
    if desconhecidos:
        print("Atenção: há aparelhos fora do seu inventário. Confira os MACs com os seus aparelhos.")
        print("Para cadastrar os seus aparelhos, rode:  python ferramenta_rede\\monitor.py --registrar")


def registrar(dispositivos):
    """
    Modo registro: pergunta o nome de cada aparelho desconhecido
    e salva no inventário (dispositivos_conhecidos.json).
    """
    conhecidos = carregar_conhecidos()
    pendentes = [d for d in dispositivos if not d["conhecido"]]

    if not pendentes:
        print("\nTodos os aparelhos já estão no inventário.")
        return

    print("\n=== MODO REGISTRO ===")
    print("Compare o MAC de cada linha com o MAC mostrado nas configurações do aparelho.")
    print("Digite um nome (ex: iPhone da Maria) e aperte Enter. Só Enter = pular.\n")

    for d in pendentes:
        print(f"IP {d['ip']}  |  MAC {d['mac']}  |  {d['fabricante']}")
        nome = input("Nome deste aparelho: ").strip()
        if nome:
            conhecidos[d["mac"]] = nome
        print()

    salvar_conhecidos(conhecidos)
    print(f"Inventário salvo em: {ARQUIVO_CONHECIDOS}")


if __name__ == "__main__":
    faixa = "192.168.0.0/24"
    modo_registro = "--registrar" in sys.argv

    print(f"Escaneando a rede {faixa} (ping sweep + latência)...\n")

    dispositivos = escanear(faixa)

    if not dispositivos:
        print("Nenhum dispositivo encontrado.")
        sys.exit(1)

    imprimir_tabela(dispositivos)

    if not any(d.get("este_pc") for d in dispositivos):
        print(f"\nAviso: não consegui identificar este PC dentro da faixa {faixa}.")

    if modo_registro:
        registrar(dispositivos)