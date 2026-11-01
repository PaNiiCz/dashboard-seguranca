"""saude.py - nota de saúde da MINHA rede (sem precisar do painel do roteador).

Uso:  python saude.py
      python saude.py --rede 192.168.1
"""
import argparse
import re
import socket
import subprocess

try:
    from verificacao import verificar, PORTAS
except ImportError:
    from .verificacao import verificar, PORTAS


def _rodar(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        return ""
    for enc in ("utf-8", "cp850", "cp1252"):
        try:
            return r.stdout.decode(enc)
        except UnicodeDecodeError:
            continue
    return r.stdout.decode("utf-8", errors="replace")


def wifi_atual():
    """Lê o Wi-Fi atual com o netsh (português e inglês)."""
    txt = _rodar(["netsh", "wlan", "show", "interfaces"])
    info = {}
    for linha in txt.splitlines():
        if ":" not in linha:
            continue
        chave, _, valor = linha.partition(":")
        chave = chave.strip().lower()
        valor = valor.strip()
        if chave == "ssid":
            info["ssid"] = valor
        elif chave.startswith("autentic") or chave.startswith("authentic"):
            info["auth"] = valor
        elif chave.startswith("cifra") or chave.startswith("cipher"):
            info["cifra"] = valor
    return info


def avaliar_autenticacao(auth):
    a = auth.lower().replace(" ", "")
    if "wpa3" in a:
        return "otimo"
    if "wpa2" in a:
        return "ok"
    if "wep" in a or "aberta" in a or "open" in a:
        return "critico"
    if "wpa" in a:
        return "ruim"
    return "desconhecido"


NOME_PADRAO = re.compile(r"^(CLARO|NET)[_-]?(2G|5G)?[_-]?[0-9A-F]{6}$", re.IGNORECASE)


def meu_ip(rede):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((f"{rede}.1", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def checar(rede):
    itens = []  # (nivel, texto)  nivel: ok | aviso | ruim
    pontos = 100

    # 1) Wi-Fi
    wifi = wifi_atual()
    if not wifi.get("auth"):
        itens.append(("aviso", "Não consegui ler o Wi-Fi. Conecte o PC por Wi-Fi e "
                      "ligue os Serviços de localização do Windows."))
    else:
        nivel = avaliar_autenticacao(wifi["auth"])
        if nivel == "otimo":
            itens.append(("ok", f"Segurança do Wi-Fi: {wifi['auth']} (excelente)."))
        elif nivel == "ok":
            itens.append(("ok", f"Segurança do Wi-Fi: {wifi['auth']} (boa, "
                          "o máximo que o seu modem suporta)."))
        elif nivel == "ruim":
            pontos -= 25
            itens.append(("ruim", f"Segurança do Wi-Fi: {wifi['auth']} (antiga e fraca)."))
        elif nivel == "critico":
            pontos -= 40
            itens.append(("ruim", f"Segurança do Wi-Fi: {wifi['auth']} (inaceitável)."))
        else:
            pontos -= 5
            itens.append(("aviso", f"Segurança do Wi-Fi não reconhecida: {wifi['auth']}."))

        cifra = wifi.get("cifra", "")
        if "tkip" in cifra.lower():
            pontos -= 15
            itens.append(("aviso", f"Cifra {cifra}: antiga. O ideal é CCMP/AES."))

        ssid = wifi.get("ssid", "")
        if ssid and NOME_PADRAO.match(ssid):
            pontos -= 20
            itens.append(("ruim", f"O nome da rede ({ssid}) é o de fábrica. Isso sugere "
                          "que a senha também é a de fábrica, que é previsível. "
                          "Troque o nome e a senha do Wi-Fi."))
        elif ssid:
            itens.append(("ok", f"O nome da rede ({ssid}) não é o padrão de fábrica."))

    # 2) Portas de risco nos aparelhos
    print("Verificando portas dos aparelhos... aguarde.")
    abertas = verificar([f"{rede}.{i}" for i in range(1, 255)])
    meu = meu_ip(rede)
    achou_risco = False
    for ip in sorted(abertas, key=lambda x: tuple(int(n) for n in x.split("."))):
        for p in sorted(abertas[ip]):
            servico, risco, obs = PORTAS[p]
            if risco == "ALTO":
                pontos -= 25
                achou_risco = True
                itens.append(("ruim", f"{ip}: porta {p} ({servico}) aberta - {obs}."))
            elif risco == "médio":
                if ip == meu:
                    itens.append(("aviso", f"{ip} (este PC): porta {p} ({servico}) "
                                  f"aberta - {obs}. Normal no Windows, sem desconto."))
                else:
                    pontos -= 5
                    achou_risco = True
                    itens.append(("aviso", f"{ip}: porta {p} ({servico}) aberta - {obs}."))
    if not achou_risco:
        itens.append(("ok", "Nenhum aparelho (fora este PC) com serviço de risco aberto."))

    return max(pontos, 0), itens


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rede", default="192.168.0", help="prefixo, ex: 192.168.0")
    args = ap.parse_args()

    nota, itens = checar(args.rede)
    marcas = {"ok": "[OK]", "aviso": "[!] ", "ruim": "[X] "}

    print("\n=== Saúde da rede ===")
    for nivel, texto in itens:
        print(f"{marcas[nivel]} {texto}")

    if nota >= 85:
        faixa = "BOA"
    elif nota >= 65:
        faixa = "RAZOÁVEL"
    else:
        faixa = "FRACA"
    print(f"\nNota: {nota}/100  ({faixa})")
    print("Limite: esta nota NÃO testa a força da senha do Wi-Fi. "
          "Isso será feito no módulo Auditoria WiFi.")


if __name__ == "__main__":
    main()