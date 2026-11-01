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

# Estados do Windows que indicam um vizinho de verdade (com MAC resolvido)
ESTADOS_VALIDOS = {"Reachable", "Stale", "Probe", "Delay"}

# Um único PowerShell coleta tudo de uma vez: vizinhos (IP, MAC e estado),
# rotas, DNS e o nome da rede (perfil) de cada placa.
SCRIPT_REDE = (
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
    "$viz = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
    "Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, "
    "@{n='State';e={$_.State.ToString()}}; "
    "$rotas = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
    "-ErrorAction SilentlyContinue | Select-Object InterfaceAlias, NextHop, RouteMetric; "
    "$dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
    "Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias, ServerAddresses; "
    "$perfis = Get-NetConnectionProfile -ErrorAction SilentlyContinue | "
    "Select-Object InterfaceAlias, Name; "
    "@{ vizinhos = @($viz); rotas = @($rotas); dns = @($dns); perfis = @($perfis) } | "
    "ConvertTo-Json -Depth 4 -Compress"
)


def pingar(ip):
    """Ping rápido (1 pacote, timeout curto). Retorna True se o IP respondeu."""
    resultado = subprocess.run(
        ["ping", "-n", "1", "-w", "300", str(ip)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=SEM_JANELA,
    )
    return resultado.returncode == 0


def ping_sweep(faixa_cidr):
    """Ping em paralelo em toda a faixa, para o Windows descobrir quem está ativo."""
    rede = ipaddress.ip_network(faixa_cidr, strict=False)
    ips = [str(ip) for ip in rede.hosts()]

    with ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(pingar, ips))


def ler_tabela_arp(faixa_cidr):
    """
    Plano B: lê o 'arp -a' (sem estado). Só é usado se o PowerShell falhar.
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


def _como_lista(valor):
    if valor is None:
        return []
    if isinstance(valor, dict):
        return [valor]
    return [item for item in valor if isinstance(item, dict)]


def coletar_rede():
    """
    Pergunta ao Windows (PowerShell) pelos vizinhos da rede, rotas, DNS e
    perfis de rede. Devolve um dicionário ou None se não conseguir.
    """
    try:
        saida = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", SCRIPT_REDE],
            capture_output=True,
            text=True,
            encoding="utf-8-sig",
            errors="replace",
            creationflags=SEM_JANELA,
            timeout=30,
        ).stdout
        dados = json.loads(saida)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None

    if not isinstance(dados, dict):
        return None
    return {
        chave: _como_lista(dados.get(chave))
        for chave in ("vizinhos", "rotas", "dns", "perfis")
    }


def vizinhos_da_faixa(rede, faixa_cidr):
    """
    Filtra os vizinhos que estão na faixa e têm MAC de verdade.
    'estado_arp' = 'Reachable' significa que o aparelho respondeu agora há pouco
    (mesmo que ele ignore ping). 'Stale' = já foi visto, mas não agora.
    """
    faixa = ipaddress.ip_network(faixa_cidr, strict=False)
    resultado = []
    for v in rede["vizinhos"]:
        ip = v.get("IPAddress")
        mac = (v.get("LinkLayerAddress") or "").replace("-", ":").lower()
        estado = v.get("State")

        try:
            if ipaddress.ip_address(ip) not in faixa:
                continue
        except ValueError:
            continue

        if estado not in ESTADOS_VALIDOS:
            continue
        if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            continue
        # Ignora MAC zerado, broadcast e multicast (bit de grupo ligado)
        if int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00":
            continue

        resultado.append({"ip": ip, "mac": mac, "estado_arp": estado})

    return resultado


def alias_da_faixa(rede, faixa_cidr):
    """Nome da placa de rede (ex: 'Wi-Fi') que enxerga a faixa escaneada."""
    faixa = ipaddress.ip_network(faixa_cidr, strict=False)
    contagem = {}
    for v in rede["vizinhos"]:
        try:
            if ipaddress.ip_address(v.get("IPAddress")) not in faixa:
                continue
        except ValueError:
            continue
        alias = v.get("InterfaceAlias")
        if alias:
            contagem[alias] = contagem.get(alias, 0) + 1
    return max(contagem, key=contagem.get) if contagem else None


def info_rede(rede, alias):
    """Gateway (roteador) e servidores DNS da placa 'alias'."""
    gateway = None
    rotas = [
        r
        for r in rede["rotas"]
        if r.get("InterfaceAlias") == alias and r.get("NextHop") not in (None, "", "0.0.0.0")
    ]
    if rotas:
        gateway = min(rotas, key=lambda r: r.get("RouteMetric") or 0)["NextHop"]

    dns = []
    for item in rede["dns"]:
        if item.get("InterfaceAlias") == alias:
            servidores = item.get("ServerAddresses")
            dns = [servidores] if isinstance(servidores, str) else list(servidores or [])
    return {"gateway": gateway, "dns": dns}


def mac_privado(mac):
    """
    MAC 'privado/aleatório' (celulares com endereço Wi-Fi privado): o segundo
    dígito hexadecimal do MAC é 2, 6, A ou E.
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
    IP deste computador DENTRO da faixa escaneada. O 'connect' em UDP não
    envia nada: só faz o Windows escolher a placa que alcança aquela faixa.
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
    """Tenta descobrir o nome do aparelho perguntando ao DNS da rede."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def medir_latencia(ip, tentativas=3):
    """Devolve (latencia_media_ms, perda_percentual). Sem resposta: latência None."""
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


def classificar_status(media, perda, estado_arp=None):
    if media is None:
        # Não responde ping, mas respondeu à rede (ARP): está conectado
        return "sem ping" if estado_arp == "Reachable" else "offline"
    if perda >= 50 or media >= 250:
        return "ruim"
    if perda > 0 or media >= 100:
        return "atenção"
    return "saudável"


def carregar_conhecidos():
    """Lê o inventário de aparelhos conhecidos: { "mac": "nome" }."""
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
    dispositivo["status"] = classificar_status(media, perda, dispositivo.get("estado_arp"))
    dispositivo["nome_rede"] = nome_na_rede(dispositivo["ip"])
    return dispositivo


def escanear_completo(faixa_cidr):
    """
    Varre a rede e devolve (dispositivos, rede). Cada dispositivo tem: ip, mac,
    estado_arp, fabricante, nome, conhecido, nome_rede, latencia_ms, perda_pct,
    status e (opcional) este_pc. 'rede' traz rotas, DNS e perfis do Windows.
    """
    ping_sweep(faixa_cidr)

    # Lido logo depois do sweep, quando o estado 'Reachable' ainda está fresco
    rede = coletar_rede()
    if rede is not None and rede["vizinhos"]:
        dispositivos = vizinhos_da_faixa(rede, faixa_cidr)
    else:
        rede = rede or {"vizinhos": [], "rotas": [], "dns": [], "perfis": []}
        dispositivos = [dict(d, estado_arp=None) for d in ler_tabela_arp(faixa_cidr)]

    # O PC não aparece na própria tabela de vizinhos, então garantimos aqui
    meu_ip = ip_deste_pc(faixa_cidr)
    if meu_ip:
        existente = next((d for d in dispositivos if d["ip"] == meu_ip), None)
        if existente:
            existente["este_pc"] = True
        else:
            dispositivos.append({"ip": meu_ip, "mac": "—", "este_pc": True, "estado_arp": None})

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
    return dispositivos, rede


def escanear(faixa_cidr):
    return escanear_completo(faixa_cidr)[0]


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
    """Modo registro: pergunta o nome de cada aparelho desconhecido e salva no inventário."""
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