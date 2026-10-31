import os
import sys
import time
import socket
import ipaddress
from datetime import datetime

# Funciona tanto rodando o arquivo direto (python ferramenta_rede\painel.py)
# quanto importado como parte do pacote (from ferramenta_rede import painel).
try:
    from . import historico, monitor
except ImportError:
    import historico
    import monitor

try:
    import psutil
except ImportError:
    psutil = None

FAIXA = "192.168.0.0/24"
INTERVALO_PADRAO = 60  # segundos entre varreduras no modo --monitorar


def chave_de(dispositivo):
    """Identificador do aparelho no banco: o MAC (ou 'este-pc' para este computador)."""
    return "este-pc" if dispositivo.get("este_pc") else dispositivo["mac"]


def nome_exibicao(chave, conhecidos):
    if chave == "este-pc":
        return "(este PC)"
    return conhecidos.get(chave, "[!] DESCONHECIDO")


def formatar_bytes(quantidade):
    valor = float(quantidade)
    for unidade in ("B", "KB", "MB", "GB"):
        if valor < 1024 or unidade == "GB":
            texto = f"{valor:.0f}" if unidade == "B" else f"{valor:.1f}".replace(".", ",")
            return f"{texto} {unidade}"
        valor /= 1024


def interface_do_ip(ip):
    """Descobre qual placa de rede (ex: 'Wi-Fi') está usando o IP informado."""
    if psutil is None:
        return None
    for nome, enderecos in psutil.net_if_addrs().items():
        for endereco in enderecos:
            if endereco.family == socket.AF_INET and endereco.address == ip:
                return nome
    return None


def ler_contadores(interface):
    """Devolve (bytes_recebidos, bytes_enviados) da placa de rede."""
    if psutil is None or interface is None:
        return None
    contadores = psutil.net_io_counters(pernic=True).get(interface)
    if contadores is None:
        return None
    return contadores.bytes_recv, contadores.bytes_sent


def para_leitura(d):
    return {
        "chave": chave_de(d),
        "ip": d["ip"],
        "fabricante": d["fabricante"],
        "nome_rede": d.get("nome_rede"),
        "presente": d["latencia_ms"] is not None,
        "latencia_ms": d["latencia_ms"],
        "perda_pct": d["perda_pct"],
    }


def varrer(conexao, faixa):
    dispositivos = monitor.escanear(faixa)
    primeira_vez = conexao.execute("SELECT COUNT(*) FROM dispositivos").fetchone()[0] == 0
    eventos = historico.registrar_scan(
        conexao, [para_leitura(d) for d in dispositivos], silencioso=primeira_vez
    )
    return dispositivos, eventos, primeira_vez


def imprimir_painel(conexao, dispositivos, conhecidos, faixa, consumo, legenda):
    agora_dt = datetime.now()
    atuais = {chave_de(d): d for d in dispositivos}
    resumo = historico.resumo_aparelhos(conexao, agora_dt)
    resumo.sort(key=lambda r: (r["conectado_desde"] is None, ipaddress.ip_address(r["ip"])))

    conectados = [r for r in resumo if r["conectado_desde"]]
    desconhecidos = [
        r for r in conectados if r["chave"] != "este-pc" and r["chave"] not in conhecidos
    ]

    print(f"Painel de monitoramento Wi-Fi  |  rede {faixa}  |  {agora_dt:%d/%m/%Y %H:%M:%S}")
    print(
        f"Dispositivos conectados: {len(conectados)}  |  "
        f"Desconhecidos: {len(desconhecidos)}  |  Já vistos: {len(resumo)}\n"
    )
    print(
        f"{'Dispositivo':<22}{'IP local':<15}{'Fabricante':<25}{'Conectado há':<20}"
        f"{'Hoje':<10}{'Latência':<10}{'Consumo':<24}{'Status'}"
    )
    print("-" * 135)

    for r in resumo:
        chave = r["chave"]
        atual = atuais.get(chave)
        nome = nome_exibicao(chave, conhecidos)

        if r["conectado_desde"]:
            conectado_ha = historico.formatar_duracao(r["segundos_atual"])
            if atual and atual["latencia_ms"] is not None:
                latencia, status = f"{atual['latencia_ms']:.0f} ms", atual["status"]
            else:
                latencia, status = "—", "sem resposta"
        else:
            visto = datetime.fromisoformat(r["ultimo_visto"])
            conectado_ha = f"visto {visto:%d/%m %H:%M}"
            latencia, status = "—", "ausente"

        if chave == "este-pc" and consumo:
            texto_consumo = f"↓{formatar_bytes(consumo[0])} ↑{formatar_bytes(consumo[1])}"
        else:
            texto_consumo = "—"

        print(
            f"{nome[:20]:<22}{r['ip']:<15}{r['fabricante'][:23]:<25}{conectado_ha:<20}"
            f"{historico.formatar_duracao(r['segundos_hoje']):<10}{latencia:<10}"
            f"{texto_consumo:<24}{status}"
        )

    print(
        f"\nConsumo: só o deste PC é medido ({legenda or 'sem dados'}). "
        "O dos outros aparelhos exige integração com o roteador."
    )


def imprimir_eventos(conexao, conhecidos, limite=8):
    eventos = historico.eventos_recentes(conexao, limite)
    rotulos = {"novo": "NOVO APARELHO", "entrou": "ENTROU", "saiu": "SAIU"}

    print("\nÚltimos eventos:")
    if not eventos:
        print("  (nenhum ainda)")
        return
    for e in eventos:
        quando = datetime.fromisoformat(e["momento"]).strftime("%d/%m %H:%M:%S")
        detalhe = f"  ({e['detalhe']})" if e["detalhe"] else ""
        rotulo = rotulos.get(e["tipo"], e["tipo"])
        print(f"  {quando}  {rotulo:<15}{nome_exibicao(e['mac'], conhecidos)}{detalhe}")


def executar(faixa, intervalo=None):
    """Uma varredura (intervalo=None) ou monitoramento contínuo (intervalo em segundos)."""
    conexao = historico.conectar()
    interface = None
    base = None

    try:
        while True:
            print(f"Escaneando a rede {faixa}...")
            dispositivos, eventos, primeira_vez = varrer(conexao, faixa)
            conhecidos = monitor.carregar_conhecidos()

            # Consumo: só dá para medir o do próprio PC (pela placa de rede dele)
            meu = next((d for d in dispositivos if d.get("este_pc")), None)
            consumo, legenda = None, ""
            if meu:
                if interface is None:
                    interface = interface_do_ip(meu["ip"])
                atual = ler_contadores(interface)
                if atual:
                    if intervalo and base is None:
                        base = atual
                    if base:
                        consumo = (atual[0] - base[0], atual[1] - base[1])
                        legenda = "desde que o monitor iniciou"
                    else:
                        consumo = atual
                        legenda = "total desde que o Windows iniciou"

            if intervalo:
                os.system("cls" if os.name == "nt" else "clear")

            imprimir_painel(conexao, dispositivos, conhecidos, faixa, consumo, legenda)
            imprimir_eventos(conexao, conhecidos)

            if primeira_vez:
                print("\nPrimeira varredura: os aparelhos atuais foram guardados como ponto de partida.")
            for e in eventos:
                if e["tipo"] == "novo" and e["chave"] not in conhecidos:
                    print(f"\n[!!] ALERTA: aparelho novo e desconhecido na rede: {e['detalhe']} ({e['chave']})")

            if not intervalo:
                break
            print(f"\nPróxima varredura em {intervalo}s  (Ctrl+C para parar)")
            time.sleep(intervalo)
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado.")
    finally:
        conexao.close()


if __name__ == "__main__":
    argumentos = sys.argv[1:]

    if "--historico" in argumentos:
        conexao = historico.conectar()
        imprimir_eventos(conexao, monitor.carregar_conhecidos(), limite=30)
        conexao.close()
    elif "--monitorar" in argumentos:
        intervalo = INTERVALO_PADRAO
        posicao = argumentos.index("--monitorar")
        if posicao + 1 < len(argumentos) and argumentos[posicao + 1].isdigit():
            intervalo = min(max(10, int(argumentos[posicao + 1])), 300)
        executar(FAIXA, intervalo)
    else:
        executar(FAIXA)