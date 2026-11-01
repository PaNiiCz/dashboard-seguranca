"""
Descoberta de nomes e modelos na própria rede:
  - SSDP/UPnP: TVs, roteadores, caixas de som, aparelhos Xiaomi etc. dizem o modelo.
  - mDNS/Bonjour: iPhones, Macs, Chromecast, impressoras dizem o nome (quando acordados).
Celular com tela apagada normalmente NÃO responde: é um complemento, não uma garantia.
"""
import re
import socket
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

PEDIDO_SSDP = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


def _novo():
    return {"nomes": [], "modelos": []}


def _adicionar(lista, valor):
    valor = (valor or "").strip()
    if valor and valor not in lista:
        lista.append(valor)


def _cabecalhos(texto):
    cabecalhos = {}
    for linha in texto.split("\r\n")[1:]:
        if ":" in linha:
            chave, valor = linha.split(":", 1)
            cabecalhos[chave.strip().lower()] = valor.strip()
    return cabecalhos


def ler_descricao_upnp(url, ip_esperado):
    """
    Baixa a descrição UPnP do aparelho. Por segurança, só aceita endereços
    http cujo host seja o próprio aparelho que respondeu (nada de ser
    redirecionado para outro lugar) e lê no máximo 64 KB.
    """
    partes = urllib.parse.urlparse(url)
    if partes.scheme != "http" or partes.hostname != ip_esperado:
        return None
    try:
        with urllib.request.urlopen(url, timeout=2) as resposta:
            corpo = resposta.read(65536)
        raiz = ET.fromstring(corpo)
    except Exception:
        return None

    def texto(tag):
        elemento = raiz.find(f".//{{*}}{tag}")
        return (elemento.text or "").strip() if elemento is not None else ""

    fabricante, modelo = texto("manufacturer"), texto("modelName")
    return {
        "nome": texto("friendlyName"),
        "modelo": " ".join(p for p in (fabricante, modelo) if p),
    }


def descobrir_ssdp(ip_local, segundos=4):
    locais = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip_local))
        sock.bind((ip_local, 0))
        sock.settimeout(0.5)
        sock.sendto(PEDIDO_SSDP, ("239.255.255.250", 1900))

        fim = time.time() + segundos
        while time.time() < fim:
            try:
                dados, (ip, _porta) = sock.recvfrom(65535)
            except socket.timeout:
                continue
            location = _cabecalhos(dados.decode("utf-8", errors="replace")).get("location")
            if location:
                locais.setdefault(ip, set()).add(location)
    finally:
        sock.close()

    resultado = {}
    tarefas = [(ip, url) for ip, urls in locais.items() for url in sorted(urls)[:2]]
    with ThreadPoolExecutor(max_workers=6) as executor:
        descricoes = list(executor.map(lambda t: ler_descricao_upnp(t[1], t[0]), tarefas))
    for (ip, _url), descricao in zip(tarefas, descricoes):
        if descricao:
            item = resultado.setdefault(ip, _novo())
            _adicionar(item["nomes"], descricao["nome"])
            _adicionar(item["modelos"], descricao["modelo"])
    return resultado


def _modelo_mdns(propriedades):
    for chave in (b"model", b"md", b"am", b"ty", b"product"):
        valor = propriedades.get(chave)
        if valor:
            return valor.decode("utf-8", errors="ignore") if isinstance(valor, bytes) else str(valor)
    return ""


def descobrir_mdns(ip_local, segundos=4):
    try:
        from zeroconf import ServiceBrowser, Zeroconf, ZeroconfServiceTypes
    except ImportError:
        return {}

    encontrados = []

    class Ouvinte:
        def add_service(self, zc, tipo, nome):
            encontrados.append((tipo, nome))

        def update_service(self, zc, tipo, nome):
            pass

        def remove_service(self, zc, tipo, nome):
            pass

    resultado = {}
    zc = Zeroconf(interfaces=[ip_local])
    try:
        tipos = list(ZeroconfServiceTypes.find(zc=zc, timeout=segundos))
        if not tipos:
            return {}
        navegador = ServiceBrowser(zc, tipos, listener=Ouvinte())
        time.sleep(segundos)
        navegador.cancel()

        for tipo, nome in encontrados[:80]:
            info = zc.get_service_info(tipo, nome, timeout=1000)
            if not info:
                continue
            instancia = nome.split("._")[0]
            servidor = re.sub(r"\.local\.?$", "", (info.server or "").rstrip("."))
            modelo = _modelo_mdns(info.properties or {})
            for ip in info.parsed_addresses():
                if "." not in ip:  # só IPv4
                    continue
                item = resultado.setdefault(ip, _novo())
                _adicionar(item["nomes"], instancia)
                _adicionar(item["nomes"], servidor)
                _adicionar(item["modelos"], modelo)
    finally:
        zc.close()
    return resultado


def _resumir(item):
    nome = item["nomes"][0] if item["nomes"] else ""
    modelo = item["modelos"][0] if item["modelos"] else ""
    if nome and modelo and modelo.lower() not in nome.lower():
        return f"{nome} [{modelo}]"
    return nome or modelo


def descobrir(ip_local, segundos=4):
    """Devolve {ip: 'Nome [Modelo]'} juntando SSDP e mDNS. Qualquer falha vira resultado vazio."""
    juntos = {}

    def seguro(funcao):
        try:
            return funcao(ip_local, segundos)
        except Exception:
            return {}

    with ThreadPoolExecutor(max_workers=2) as executor:
        resultados = list(executor.map(seguro, (descobrir_ssdp, descobrir_mdns)))

    for parcial in resultados:
        for ip, item in parcial.items():
            destino = juntos.setdefault(ip, _novo())
            for nome in item["nomes"]:
                _adicionar(destino["nomes"], nome)
            for modelo in item["modelos"]:
                _adicionar(destino["modelos"], modelo)

    return {ip: _resumir(item) for ip, item in juntos.items() if _resumir(item)}