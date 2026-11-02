"""uso_rede.py - visão aproximada de quem está usando mais a internet AGORA.

Limite importante: o Windows não expõe quantos bytes cada processo consumiu sem
um driver de captura extra. O que dá para fazer é contar as conexões ATIVAS de
cada processo com a internet - é uma aproximação (muitas conexões geralmente
indica mais uso), não uma medição exata de Mbps por processo.
"""
import time

import psutil


def processos_mais_ativos(limite=10):
    contagem = {}
    try:
        conexoes = psutil.net_connections(kind="inet")
    except psutil.AccessDenied as erro:
        raise PermissionError(
            "Sem permissão para ver as conexões de outros processos. "
            "Feche e abra o terminal como Administrador."
        ) from erro

    for c in conexoes:
        if not c.raddr or c.status != psutil.CONN_ESTABLISHED or not c.pid:
            continue
        try:
            nome = psutil.Process(c.pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            nome = f"PID {c.pid}"
        contagem[nome] = contagem.get(nome, 0) + 1

    return sorted(contagem.items(), key=lambda item: item[1], reverse=True)[:limite]


def taxa_atual(intervalo=1.0):
    """Taxa de download/upload da MÁQUINA toda (todas as interfaces) no momento, em Mbps."""
    antes = psutil.net_io_counters()
    time.sleep(intervalo)
    depois = psutil.net_io_counters()
    download = (depois.bytes_recv - antes.bytes_recv) * 8 / 1_000_000 / intervalo
    upload = (depois.bytes_sent - antes.bytes_sent) * 8 / 1_000_000 / intervalo
    return round(download, 2), round(upload, 2)