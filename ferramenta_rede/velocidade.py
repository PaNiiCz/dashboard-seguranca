"""velocidade.py - teste de velocidade da internet (como o Speedtest), com
histórico próprio em SQLite para detectar queda em relação ao normal.
"""
import sqlite3
import statistics
import time
from pathlib import Path

try:
    import speedtest
except ImportError:
    speedtest = None

ARQUIVO_BANCO = Path(__file__).parent / "velocidade_historico.db"


class ErroVelocidade(Exception):
    pass


def conectar():
    conexao = sqlite3.connect(ARQUIVO_BANCO)
    conexao.execute("""
        CREATE TABLE IF NOT EXISTS medicoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            momento TEXT NOT NULL,
            download_mbps REAL NOT NULL,
            upload_mbps REAL NOT NULL,
            ping_ms REAL NOT NULL,
            servidor TEXT
        )
    """)
    conexao.commit()
    return conexao


def medir():
    """Roda um teste de velocidade real (usa dados da sua internet). Leva 15-30s."""
    if speedtest is None:
        raise ErroVelocidade(
            "O pacote 'speedtest-cli' não está instalado. Rode: pip install speedtest-cli"
        )
    try:
        st = speedtest.Speedtest(secure=True)
        st.get_best_server()
        download = st.download() / 1_000_000  # bits/s -> Mbps
        upload = st.upload() / 1_000_000
        ping = st.results.ping
        servidor = st.results.server.get("sponsor", "?")
    except Exception as erro:
        raise ErroVelocidade(f"Falha ao medir: {type(erro).__name__}: {erro}") from erro

    return {
        "download_mbps": round(download, 1),
        "upload_mbps": round(upload, 1),
        "ping_ms": round(ping, 1),
        "servidor": servidor,
    }


def registrar(conexao, resultado):
    conexao.execute(
        "INSERT INTO medicoes (momento, download_mbps, upload_mbps, ping_ms, servidor) "
        "VALUES (datetime('now','localtime'), ?, ?, ?, ?)",
        (resultado["download_mbps"], resultado["upload_mbps"], resultado["ping_ms"], resultado["servidor"]),
    )
    conexao.commit()


def historico_recente(conexao, limite=20):
    cursor = conexao.execute(
        "SELECT momento, download_mbps, upload_mbps, ping_ms, servidor "
        "FROM medicoes ORDER BY id DESC LIMIT ?", (limite,)
    )
    colunas = [c[0] for c in cursor.description]
    return [dict(zip(colunas, linha)) for linha in cursor.fetchall()]


def avaliar(atual, historico_anterior):
    """Compara a medição atual com a média das anteriores. Devolve lista de avisos."""
    avisos = []
    if len(historico_anterior) < 3:
        return avisos  # ainda não há uma média confiável

    media_download = statistics.mean(h["download_mbps"] for h in historico_anterior)
    media_ping = statistics.mean(h["ping_ms"] for h in historico_anterior)

    if media_download > 0 and atual["download_mbps"] < media_download * 0.5:
        avisos.append(
            f"Download caiu para {atual['download_mbps']} Mbps, menos da metade da média "
            f"recente ({media_download:.1f} Mbps). Pode ser instabilidade da operadora, "
            "muitos aparelhos usando a rede, ou o Wi-Fi congestionado."
        )
    if media_ping > 0 and atual["ping_ms"] > media_ping * 2 and atual["ping_ms"] > 80:
        avisos.append(
            f"Ping subiu para {atual['ping_ms']} ms (média recente: {media_ping:.1f} ms). "
            "Pode indicar congestionamento momentâneo."
        )
    if not avisos:
        avisos.append("Dentro do normal em relação às últimas medições.")
    return avisos