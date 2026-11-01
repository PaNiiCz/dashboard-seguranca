"""
Ambiente Wi-Fi: lê o que a placa do seu PC enxerga (via 'netsh wlan') e procura
sinais de problema: segurança fraca na sua rede e pontos de acesso "gêmeos"
(rede com o mesmo nome da sua, mas que não é o seu roteador nem um repetidor seu).
No Windows 11 o netsh só funciona com os Serviços de localização ligados.
"""
import re
import subprocess
import unicodedata

SEM_JANELA = getattr(subprocess, "CREATE_NO_WINDOW", 0)

CAMPOS_INTERFACE = {
    "ssid": "ssid", "bssid": "bssid",
    "autenticacao": "autenticacao", "authentication": "autenticacao",
    "cifra": "cifra", "cipher": "cifra",
    "banda": "banda", "band": "banda",
    "canal": "canal", "channel": "canal",
    "sinal": "sinal", "signal": "sinal",
    "tipo de radio": "radio", "radio type": "radio",
}
CAMPOS_REDE = {
    "autenticacao": "autenticacao", "authentication": "autenticacao",
    "criptografia": "criptografia", "encryption": "criptografia",
}
CAMPOS_BSSID = {
    "sinal": "sinal", "signal": "sinal",
    "canal": "canal", "channel": "canal",
    "banda": "banda", "band": "banda",
    "tipo de radio": "radio", "radio type": "radio",
}

MSG_LOCALIZACAO = (
    "O Windows bloqueou a leitura do Wi-Fi: ligue os Serviços de localização em "
    "Configurações > Privacidade e segurança > Localização "
    "(atalho: Win+R e digite  ms-settings:privacy-location ). "
    "Se continuar, reinicie o serviço 'Configuração Automática de WLAN'."
)


class ErroWifi(Exception):
    pass


def _normalizar(texto):
    sem_acento = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    return sem_acento.strip().lower()


def _netsh(*args):
    try:
        resultado = subprocess.run(
            ["netsh", "wlan", *args],
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="replace",
            creationflags=SEM_JANELA,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as erro:
        raise ErroWifi(f"Não consegui rodar o netsh: {erro}")
    return resultado.stdout


def interpretar_interface(texto):
    """Lê a saída de 'netsh wlan show interfaces' (português ou inglês)."""
    dados = {}
    for linha in texto.splitlines():
        if ":" not in linha:
            continue
        chave, valor = linha.split(":", 1)
        campo = CAMPOS_INTERFACE.get(_normalizar(chave))
        if campo and campo not in dados:  # só o primeiro bloco de interface
            dados[campo] = valor.strip()
    return dados if dados.get("ssid") else None


def interpretar_redes(texto):
    """Lê a saída de 'netsh wlan show networks mode=bssid'."""
    redes, rede, bssid = [], None, None
    for linha in texto.splitlines():
        m = re.match(r"^\s*SSID\s+\d+\s*:\s*(.*)$", linha)
        if m:
            rede = {"ssid": m.group(1).strip(), "autenticacao": "", "criptografia": "", "bssids": []}
            redes.append(rede)
            bssid = None
            continue
        m = re.match(r"^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})", linha)
        if m and rede is not None:
            bssid = {"bssid": m.group(1).lower(), "sinal": "", "canal": "", "banda": "", "radio": ""}
            rede["bssids"].append(bssid)
            continue
        if ":" in linha and rede is not None:
            chave, valor = linha.split(":", 1)
            campo, valor = _normalizar(chave), valor.strip()
            if bssid is not None and campo in CAMPOS_BSSID:
                bssid[CAMPOS_BSSID[campo]] = valor
            elif bssid is None and campo in CAMPOS_REDE:
                rede[CAMPOS_REDE[campo]] = valor
    return redes


def _parece_bloqueio(texto):
    return bool(
        re.search(
            r"location|localiza|permission|permiss|access is denied|acesso negado",
            texto,
            re.IGNORECASE,
        )
    )


def ler_interface():
    """Dados da sua conexão Wi-Fi atual (ou None se não estiver no Wi-Fi)."""
    texto = _netsh("show", "interfaces")
    dados = interpretar_interface(texto)
    if dados is None and _parece_bloqueio(texto):
        raise ErroWifi(MSG_LOCALIZACAO)
    return dados


def escanear_redes():
    """Redes Wi-Fi ao redor, com cada ponto de acesso (BSSID)."""
    texto = _netsh("show", "networks", "mode=bssid")
    redes = interpretar_redes(texto)
    if not redes:
        if _parece_bloqueio(texto):
            raise ErroWifi(MSG_LOCALIZACAO)
        raise ErroWifi("Nenhuma rede Wi-Fi foi listada pelo Windows (Wi-Fi desligado?).")
    return redes


def _eh_fraca(autenticacao):
    a = autenticacao.lower()
    if "wpa3" in a or "wpa2" in a:
        return False
    return any(x in a for x in ("wep", "open", "abert", "wpa"))


def analisar(interface, redes, referencias):
    """
    Devolve (alertas, a_gravar). 'referencias' guarda os pontos de acesso (BSSIDs)
    já conhecidos da SUA rede; na primeira vez, os que aparecem viram a linha de base.
    """
    alertas, a_gravar = [], {}
    if not interface:
        return alertas, a_gravar

    ssid = interface["ssid"]
    minha_auth = interface.get("autenticacao", "")

    if minha_auth and _eh_fraca(minha_auth):
        alertas.append(
            {
                "chave": "wifi_fraco",
                "nivel": "alto",
                "mensagem": f"A sua rede '{ssid}' usa segurança fraca ({minha_auth}). Use WPA2 ou WPA3.",
            }
        )

    vistos = {}
    for rede in redes:
        if rede["ssid"] != ssid:
            continue
        diferente = bool(minha_auth) and rede["autenticacao"].lower() != minha_auth.lower()
        for ponto in rede["bssids"]:
            vistos[ponto["bssid"]] = (ponto, diferente, rede["autenticacao"])
    if interface.get("bssid"):
        vistos.setdefault(interface["bssid"].lower(), ({"sinal": "", "canal": ""}, False, minha_auth))

    if "bssids" not in referencias:
        a_gravar["bssids"] = ",".join(sorted(vistos))
        return alertas, a_gravar

    conhecidos = set(filter(None, referencias["bssids"].split(",")))
    for bssid, (ponto, seguranca_diferente, auth) in sorted(vistos.items()):
        if bssid in conhecidos:
            continue
        detalhe = f"sinal {ponto.get('sinal') or '?'}, canal {ponto.get('canal') or '?'}"
        if seguranca_diferente:
            alertas.append(
                {
                    "chave": f"rede_falsa:{bssid}",
                    "nivel": "alto",
                    "mensagem": (
                        f"Existe uma rede com o MESMO nome da sua ('{ssid}') mas com segurança "
                        f"diferente ({auth or 'aberta'}), no ponto {bssid} ({detalhe}). "
                        "Pode ser uma rede falsa (evil twin)."
                    ),
                }
            )
        else:
            alertas.append(
                {
                    "chave": f"ponto_novo:{bssid}",
                    "nivel": "medio",
                    "mensagem": (
                        f"Novo ponto de acesso com o nome da sua rede ('{ssid}'): {bssid} ({detalhe}). "
                        "Se for um repetidor/mesh seu, rode  --aceitar-referencias ; "
                        "se não for, pode ser uma rede falsa."
                    ),
                }
            )
    return alertas, a_gravar


def _banda(ponto):
    if ponto.get("banda"):
        return ponto["banda"]
    try:
        return "2,4 GHz" if int(ponto.get("canal", "0")) <= 14 else "5 GHz"
    except ValueError:
        return "?"


def imprimir_relatorio(interface, redes):
    print("Sua conexão Wi-Fi:")
    if interface:
        print(f"  Rede: {interface['ssid']}   Ponto de acesso (BSSID): {interface.get('bssid', '?')}")
        print(
            f"  Banda: {interface.get('banda', '?')}   Canal: {interface.get('canal', '?')}   "
            f"Sinal: {interface.get('sinal', '?')}   Rádio: {interface.get('radio', '?')}"
        )
        print(f"  Segurança: {interface.get('autenticacao', '?')} / {interface.get('cifra', '?')}")
    else:
        print("  (este PC não está conectado por Wi-Fi)")

    print(f"\nRedes ao redor: {len(redes)}")
    print(f"  {'Rede':<28}{'Segurança':<18}{'Pontos':<8}{'Melhor sinal':<14}Canais")
    print("  " + "-" * 82)
    ordenadas = sorted(redes, key=lambda r: -max((int(re.sub(r"\D", "", p["sinal"]) or 0) for p in r["bssids"]), default=0))
    for rede in ordenadas:
        sinais = [int(re.sub(r"\D", "", p["sinal"]) or 0) for p in rede["bssids"]]
        canais = sorted({p["canal"] for p in rede["bssids"] if p["canal"]}, key=lambda c: int(c) if c.isdigit() else 0)
        nome = rede["ssid"] or "(oculta)"
        print(
            f"  {nome[:26]:<28}{rede['autenticacao'][:16]:<18}{len(rede['bssids']):<8}"
            f"{(str(max(sinais)) + '%') if sinais else '?':<14}{', '.join(canais)}"
        )

    uso = {}
    for rede in redes:
        for ponto in rede["bssids"]:
            if ponto["canal"]:
                chave = (_banda(ponto), ponto["canal"])
                uso[chave] = uso.get(chave, 0) + 1
    if uso:
        print("\nCanais mais ocupados:")
        for (banda, canal), qtd in sorted(uso.items(), key=lambda x: -x[1])[:6]:
            print(f"  {banda} canal {canal}: {qtd} ponto(s) de acesso")