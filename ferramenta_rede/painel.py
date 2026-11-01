import os
import sys
import time
import socket
import ipaddress
import threading
from datetime import datetime

# Funciona tanto rodando o arquivo direto (python ferramenta_rede\painel.py)
# quanto importado como parte do pacote (from ferramenta_rede import painel).
try:
    from . import ambiente_wifi, descoberta, historico, monitor, notificacoes, seguranca
except ImportError:
    import ambiente_wifi
    import descoberta
    import historico
    import monitor
    import notificacoes
    import seguranca

try:
    import psutil
except ImportError:
    psutil = None

FAIXA = "192.168.0.0/24"
INTERVALO_PADRAO = 60    # segundos entre varreduras no modo --monitorar
DESCOBERTA_A_CADA = 600  # segundos entre buscas de nomes/modelos (mDNS/SSDP)

AJUDA = """Uso: python ferramenta_rede\\painel.py [opção]

  (sem opção)              uma varredura e o painel
  --monitorar [segundos]   monitoramento contínuo (padrão 60 s; mínimo 10, máximo 300)
  --descobrir              também procura nomes e modelos (mDNS/SSDP) nesta varredura
  --ambiente               relatório do Wi-Fi ao redor (segurança, canais, redes gêmeas)
  --historico              mostra os últimos 30 eventos, sem escanear
  --aceitar-referencias    aceita o estado atual da rede como o normal (após trocar
                           roteador, DNS ou instalar um repetidor seu)
"""


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


def identificar_rede(rede, interface):
    """Nome da rede (perfil do Windows), usado para guardar as referências de segurança."""
    if rede and interface:
        for perfil in rede["perfis"]:
            if perfil.get("InterfaceAlias") == interface and perfil.get("Name"):
                return perfil["Name"]
    return interface or "padrao"


def para_leitura(d):
    # Presente = respondeu ao ping OU respondeu à rede (ARP 'Reachable'), mesmo ignorando ping
    presente = d["latencia_ms"] is not None or d.get("estado_arp") == "Reachable"
    return {
        "chave": chave_de(d),
        "ip": d["ip"],
        "fabricante": d["fabricante"],
        "nome_rede": d.get("nome_rede"),
        "descoberto": d.get("descoberto"),
        "presente": presente,
        "latencia_ms": d["latencia_ms"],
        "perda_pct": d["perda_pct"],
    }


def registrar_varredura(conexao, dispositivos):
    primeira_vez = conexao.execute("SELECT COUNT(*) FROM dispositivos").fetchone()[0] == 0
    eventos = historico.registrar_scan(
        conexao, [para_leitura(d) for d in dispositivos], silencioso=primeira_vez
    )
    return eventos, primeira_vez


def verificar_seguranca(conexao, rede, interface, dispositivos):
    """Roda as checagens (roteador, DNS, MACs repetidos, Wi-Fi). Devolve (alertas, avisos)."""
    rede_id = identificar_rede(rede, interface)
    referencias = historico.referencias_da_rede(conexao, rede_id)
    info = monitor.info_rede(rede, interface) if interface else {"gateway": None, "dns": []}

    alertas, a_gravar = seguranca.verificar(referencias, dispositivos, info["gateway"], info["dns"])
    avisos = []

    try:
        wifi = ambiente_wifi.ler_interface()
        redes = ambiente_wifi.escanear_redes() if wifi else []
        extras, extras_gravar = ambiente_wifi.analisar(wifi, redes, referencias)
        alertas += extras
        a_gravar.update(extras_gravar)
    except ambiente_wifi.ErroWifi as erro:
        avisos.append(str(erro))

    if a_gravar:
        historico.gravar_referencias(conexao, rede_id, a_gravar)
    return alertas, avisos


def avisar(titulo, mensagem):
    """Dispara a notificação em segundo plano (para não travar o monitor)."""
    tarefa = threading.Thread(target=notificacoes.notificar, args=(titulo, mensagem), daemon=True)
    tarefa.start()
    return tarefa


def imprimir_painel(conexao, dispositivos, conhecidos, faixa, consumo, legenda):
    agora_dt = datetime.now()
    atuais = {chave_de(d): d for d in dispositivos}
    resumo = historico.resumo_aparelhos(conexao, agora_dt)
    resumo.sort(key=lambda r: (r["conectado_desde"] is None, ipaddress.ip_address(r["ip"])))

    conectados = [r for r in resumo if r["conectado_desde"]]
    desconhecidos = [
        r for r in conectados if r["chave"] != "este-pc" and r["chave"] not in conhecidos
    ]
    monitorado = historico.formatar_duracao(historico.cobertura_hoje(conexao, agora_dt))

    print(f"Painel de monitoramento Wi-Fi  |  rede {faixa}  |  {agora_dt:%d/%m/%Y %H:%M:%S}")
    print(
        f"Dispositivos conectados: {len(conectados)}  |  Desconhecidos: {len(desconhecidos)}  |  "
        f"Já vistos: {len(resumo)}  |  Monitorado hoje: {monitorado}\n"
    )
    print(
        f"{'Dispositivo':<22}{'IP local':<15}{'Fabricante / descoberto':<30}{'Conectado há':<20}"
        f"{'Hoje':<10}{'Latência':<10}{'Consumo':<24}{'Status'}"
    )
    print("-" * 145)

    for r in resumo:
        chave = r["chave"]
        atual = atuais.get(chave)
        nome = nome_exibicao(chave, conhecidos)

        if r["conectado_desde"]:
            conectado_ha = historico.formatar_duracao(r["segundos_atual"])
            if atual:
                lat = atual["latencia_ms"]
                latencia = f"{lat:.0f} ms" if lat is not None else "—"
                status = "sem resposta" if atual["status"] == "offline" else atual["status"]
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

        identificado = r["descoberto"] or r["fabricante"]
        print(
            f"{nome[:20]:<22}{r['ip']:<15}{identificado[:28]:<30}{conectado_ha:<20}"
            f"{historico.formatar_duracao(r['segundos_hoje']):<10}{latencia:<10}"
            f"{texto_consumo:<24}{status}"
        )

    print(
        f"\nConsumo: só o deste PC é medido ({legenda or 'sem dados'}). "
        "O dos outros aparelhos exige integração com o roteador."
    )
    print("Fora do horário em que o monitor roda, não há como saber quem estava na rede.")


def imprimir_alertas(alertas, avisos):
    print("\nAlertas de segurança:")
    if not alertas:
        print("  Nenhum alerta (checados: MAC do roteador, MACs repetidos, DNS e rede Wi-Fi).")
    for alerta in alertas:
        print(f"  [{alerta['nivel'].upper()}] {alerta['mensagem']}")
    for aviso in avisos:
        print(f"  (aviso) {aviso}")


def imprimir_eventos(conexao, conhecidos, limite=8):
    eventos = historico.eventos_recentes(conexao, limite)
    rotulos = {
        "novo": "NOVO APARELHO",
        "entrou": "ENTROU",
        "saiu": "SAIU",
        "retomada": "MONITOR RETOMADO",
        "alerta": "ALERTA",
    }

    print("\nÚltimos eventos:")
    if not eventos:
        print("  (nenhum ainda)")
        return
    for e in eventos:
        quando = datetime.fromisoformat(e["momento"]).strftime("%d/%m %H:%M:%S")
        rotulo = rotulos.get(e["tipo"], e["tipo"])
        if e["tipo"] in ("retomada", "alerta"):
            print(f"  {quando}  {rotulo:<18}{e['detalhe']}")
        else:
            detalhe = f"  ({e['detalhe']})" if e["detalhe"] else ""
            print(f"  {quando}  {rotulo:<18}{nome_exibicao(e['mac'], conhecidos)}{detalhe}")


def mostrar_ambiente():
    try:
        interface = ambiente_wifi.ler_interface()
        redes = ambiente_wifi.escanear_redes()
    except ambiente_wifi.ErroWifi as erro:
        print(erro)
        return
    ambiente_wifi.imprimir_relatorio(interface, redes)


def aceitar_referencias():
    rede = monitor.coletar_rede()
    if rede is None:
        print("Não consegui ler a rede do Windows agora.")
        return
    interface = monitor.alias_da_faixa(rede, FAIXA)
    rede_id = identificar_rede(rede, interface)
    conexao = historico.conectar()
    historico.apagar_referencias(conexao, rede_id)
    conexao.close()
    print(f"Referências da rede '{rede_id}' apagadas.")
    print("Na próxima varredura, o estado atual (roteador, DNS e pontos de acesso) vira o novo normal.")


def executar(faixa, intervalo=None, descobrir_agora=False):
    """Uma varredura (intervalo=None) ou monitoramento contínuo (intervalo em segundos)."""
    conexao = historico.conectar()
    base = None
    notificados = set()
    descobertos = {}
    ultima_descoberta = 0

    try:
        while True:
            print(f"Escaneando a rede {faixa}...")
            dispositivos, rede = monitor.escanear_completo(faixa)
            conhecidos = monitor.carregar_conhecidos()

            meu = next((d for d in dispositivos if d.get("este_pc")), None)
            interface = monitor.alias_da_faixa(rede, faixa) or (
                interface_do_ip(meu["ip"]) if meu else None
            )

            # Nomes e modelos (mDNS/SSDP): sob demanda e, no monitoramento, de tempos em tempos
            precisa = descobrir_agora or (
                intervalo and time.time() - ultima_descoberta > DESCOBERTA_A_CADA
            )
            descobrir_agora = False
            if meu and precisa:
                print("Procurando nomes e modelos na rede (mDNS/SSDP)...")
                descobertos.update(descoberta.descobrir(meu["ip"]))
                ultima_descoberta = time.time()
            for d in dispositivos:
                d["descoberto"] = descobertos.get(d["ip"])

            eventos, primeira_vez = registrar_varredura(conexao, dispositivos)

            try:
                alertas, avisos = verificar_seguranca(conexao, rede, interface, dispositivos)
            except Exception as erro:
                alertas, avisos = [], [f"A checagem de segurança falhou ({type(erro).__name__}: {erro})"]

            # Consumo: só dá para medir o do próprio PC (pela placa de rede dele)
            consumo, legenda = None, ""
            atual = ler_contadores(interface) if meu else None
            if atual:
                if intervalo and base is None:
                    base = atual
                if base:
                    consumo = (atual[0] - base[0], atual[1] - base[1])
                    legenda = "desde que o monitor iniciou"
                else:
                    consumo = atual
                    legenda = "total desde que o Windows iniciou"

            # Notificações (cada alerta/aparelho novo só uma vez por execução)
            tarefas = []
            for alerta in alertas:
                chave = f"alerta:{alerta['chave']}"
                if chave not in notificados:
                    notificados.add(chave)
                    historico.registrar_evento(conexao, "alerta", "seguranca", alerta["mensagem"])
                    tarefas.append(avisar("Alerta de segurança na rede", alerta["mensagem"]))
            novos_desconhecidos = [
                e for e in eventos if e["tipo"] == "novo" and e["chave"] not in conhecidos
            ]
            for e in novos_desconhecidos:
                tarefas.append(
                    avisar("Aparelho novo e desconhecido na rede", f"IP {e['detalhe']}  |  MAC {e['chave']}")
                )

            if intervalo:
                os.system("cls" if os.name == "nt" else "clear")

            imprimir_painel(conexao, dispositivos, conhecidos, faixa, consumo, legenda)
            imprimir_alertas(alertas, avisos)
            imprimir_eventos(conexao, conhecidos)

            if primeira_vez:
                print("\nPrimeira varredura: os aparelhos atuais foram guardados como ponto de partida.")
            for e in novos_desconhecidos:
                print(f"\n[!!] ALERTA: aparelho novo e desconhecido na rede: {e['detalhe']} ({e['chave']})")

            for tarefa in tarefas:
                tarefa.join(timeout=15)

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

    if "--ajuda" in argumentos or "-h" in argumentos:
        print(AJUDA)
    elif "--historico" in argumentos:
        conexao = historico.conectar()
        imprimir_eventos(conexao, monitor.carregar_conhecidos(), limite=30)
        conexao.close()
    elif "--ambiente" in argumentos:
        mostrar_ambiente()
    elif "--aceitar-referencias" in argumentos:
        aceitar_referencias()
    elif "--monitorar" in argumentos:
        intervalo = INTERVALO_PADRAO
        posicao = argumentos.index("--monitorar")
        if posicao + 1 < len(argumentos) and argumentos[posicao + 1].isdigit():
            intervalo = min(max(10, int(argumentos[posicao + 1])), 300)
        executar(FAIXA, intervalo, descobrir_agora="--descobrir" in argumentos)
    else:
        executar(FAIXA, descobrir_agora="--descobrir" in argumentos)