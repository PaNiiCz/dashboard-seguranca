import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

ARQUIVO_BANCO = Path(__file__).resolve().parent / "historico_rede.db"

# Quantas varreduras seguidas um aparelho pode "sumir" antes de considerarmos
# que ele saiu da rede (celular dormindo às vezes não responde a uma varredura).
FALTAS_PARA_SAIR = 3

# Se o monitor ficou mais que isso sem rodar (PC desligado, por exemplo), as
# sessões abertas são encerradas no último momento visto e NENHUM "entrou" falso
# é gerado quando o monitor volta.
LACUNA_MAXIMA = timedelta(minutes=20)


def _iso(momento_dt):
    return momento_dt.isoformat(timespec="seconds")


def _garantir_coluna(conexao, tabela, coluna, definicao):
    colunas = [linha["name"] for linha in conexao.execute(f"PRAGMA table_info({tabela})")]
    if coluna not in colunas:
        conexao.execute(f"ALTER TABLE {tabela} ADD COLUMN {coluna} {definicao}")


def conectar(caminho=None):
    """Abre (e cria ou atualiza, se precisar) o banco de dados do histórico."""
    conexao = sqlite3.connect(caminho or ARQUIVO_BANCO)
    conexao.row_factory = sqlite3.Row
    conexao.executescript(
        """
        CREATE TABLE IF NOT EXISTS dispositivos (
            mac TEXT PRIMARY KEY,
            primeiro_visto TEXT NOT NULL,
            ultimo_visto TEXT NOT NULL,
            ultimo_ip TEXT,
            fabricante TEXT,
            nome_rede TEXT,
            faltas_seguidas INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            inicio TEXT NOT NULL,
            fim TEXT
        );
        CREATE TABLE IF NOT EXISTS medicoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            momento TEXT NOT NULL,
            latencia_ms REAL,
            perda_pct REAL
        );
        CREATE TABLE IF NOT EXISTS eventos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            momento TEXT NOT NULL,
            tipo TEXT NOT NULL,
            mac TEXT NOT NULL,
            detalhe TEXT
        );
        CREATE TABLE IF NOT EXISTS varreduras (
            momento TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS referencias (
            chave TEXT PRIMARY KEY,
            valor TEXT NOT NULL,
            atualizado TEXT
        );
        """
    )
    _garantir_coluna(conexao, "dispositivos", "descoberto", "TEXT")
    return conexao


def _evento(cur, momento, tipo, chave, detalhe=""):
    cur.execute(
        "INSERT INTO eventos (momento, tipo, mac, detalhe) VALUES (?, ?, ?, ?)",
        (momento, tipo, chave, detalhe),
    )
    return {"momento": momento, "tipo": tipo, "chave": chave, "detalhe": detalhe}


def registrar_evento(conexao, tipo, chave, detalhe="", momento_dt=None):
    """Grava um evento avulso (ex: alerta de segurança)."""
    momento = _iso(momento_dt or datetime.now())
    evento = _evento(conexao.cursor(), momento, tipo, chave, detalhe)
    conexao.commit()
    return evento


def _ultima_varredura(cur):
    for tabela in ("varreduras", "medicoes"):
        linha = cur.execute(f"SELECT MAX(momento) AS m FROM {tabela}").fetchone()
        if linha["m"]:
            return datetime.fromisoformat(linha["m"])
    return None


def _fechar_sessoes_antigas(cur, momento_dt):
    limite = _iso(momento_dt - LACUNA_MAXIMA)
    cur.execute(
        """
        UPDATE sessoes
           SET fim = (SELECT ultimo_visto FROM dispositivos WHERE dispositivos.mac = sessoes.mac)
         WHERE fim IS NULL
           AND (SELECT ultimo_visto FROM dispositivos WHERE dispositivos.mac = sessoes.mac) < ?
        """,
        (limite,),
    )
    cur.execute("UPDATE dispositivos SET faltas_seguidas = 0 WHERE ultimo_visto < ?", (limite,))


def _marcar_ausente(cur, chave, momento, eventos, silencioso):
    sessao = cur.execute(
        "SELECT id FROM sessoes WHERE mac = ? AND fim IS NULL", (chave,)
    ).fetchone()
    if sessao is None:
        return

    disp = cur.execute(
        "SELECT ultimo_visto, faltas_seguidas FROM dispositivos WHERE mac = ?", (chave,)
    ).fetchone()
    faltas = disp["faltas_seguidas"] + 1

    if faltas >= FALTAS_PARA_SAIR:
        cur.execute("UPDATE sessoes SET fim = ? WHERE id = ?", (disp["ultimo_visto"], sessao["id"]))
        cur.execute("UPDATE dispositivos SET faltas_seguidas = 0 WHERE mac = ?", (chave,))
        if not silencioso:
            eventos.append(_evento(cur, momento, "saiu", chave))
    else:
        cur.execute("UPDATE dispositivos SET faltas_seguidas = ? WHERE mac = ?", (faltas, chave))


def registrar_scan(conexao, leituras, momento_dt=None, silencioso=False):
    """
    Grava o resultado de uma varredura. Cada item de 'leituras' é um dicionário com:
    chave, ip, fabricante, nome_rede, descoberto, presente (True/False),
    latencia_ms, perda_pct.

    Devolve os eventos gerados: 'novo' (primeira vez que o aparelho aparece),
    'entrou', 'saiu' e 'retomada' (o monitor voltou depois de ficar desligado).
    Com silencioso=True (primeira varredura de todas) nenhum evento é gerado.
    """
    momento_dt = momento_dt or datetime.now()
    momento = _iso(momento_dt)
    eventos = []
    cur = conexao.cursor()

    ultima = _ultima_varredura(cur)
    retomada = ultima is not None and (momento_dt - ultima) > LACUNA_MAXIMA
    sem_entradas = silencioso or retomada

    _fechar_sessoes_antigas(cur, momento_dt)

    vistos = set()
    for leitura in leituras:
        chave = leitura["chave"]
        vistos.add(chave)

        existente = cur.execute("SELECT 1 FROM dispositivos WHERE mac = ?", (chave,)).fetchone()
        if existente is None:
            cur.execute(
                "INSERT INTO dispositivos "
                "(mac, primeiro_visto, ultimo_visto, ultimo_ip, fabricante, nome_rede, "
                "descoberto, faltas_seguidas) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    chave, momento, momento, leitura["ip"], leitura["fabricante"],
                    leitura.get("nome_rede"), leitura.get("descoberto"),
                ),
            )
            if not silencioso:
                eventos.append(_evento(cur, momento, "novo", chave, leitura["ip"]))
        else:
            cur.execute(
                "UPDATE dispositivos SET ultimo_ip = ?, fabricante = ?, "
                "nome_rede = COALESCE(?, nome_rede), descoberto = COALESCE(?, descoberto) "
                "WHERE mac = ?",
                (
                    leitura["ip"], leitura["fabricante"], leitura.get("nome_rede"),
                    leitura.get("descoberto"), chave,
                ),
            )

        if leitura["presente"]:
            cur.execute(
                "UPDATE dispositivos SET ultimo_visto = ?, faltas_seguidas = 0 WHERE mac = ?",
                (momento, chave),
            )
            aberta = cur.execute(
                "SELECT 1 FROM sessoes WHERE mac = ? AND fim IS NULL", (chave,)
            ).fetchone()
            if aberta is None:
                cur.execute("INSERT INTO sessoes (mac, inicio) VALUES (?, ?)", (chave, momento))
                if not sem_entradas:
                    eventos.append(_evento(cur, momento, "entrou", chave, leitura["ip"]))
        else:
            _marcar_ausente(cur, chave, momento, eventos, silencioso)

        cur.execute(
            "INSERT INTO medicoes (mac, momento, latencia_ms, perda_pct) VALUES (?, ?, ?, ?)",
            (chave, momento, leitura["latencia_ms"], leitura["perda_pct"]),
        )

    # Aparelhos com sessão aberta que nem apareceram nesta varredura
    abertos = [linha["mac"] for linha in cur.execute("SELECT mac FROM sessoes WHERE fim IS NULL")]
    for chave in abertos:
        if chave not in vistos:
            _marcar_ausente(cur, chave, momento, eventos, silencioso)

    cur.execute("INSERT INTO varreduras (momento) VALUES (?)", (momento,))

    if retomada and not silencioso:
        parado = formatar_duracao((momento_dt - ultima).total_seconds())
        eventos.append(_evento(cur, momento, "retomada", "monitor", f"ficou {parado} sem monitorar"))

    conexao.commit()
    return eventos


def cobertura_hoje(conexao, agora_dt=None):
    """Quanto tempo de hoje o monitor realmente esteve rodando (em segundos)."""
    agora_dt = agora_dt or datetime.now()
    inicio_dia = _iso(agora_dt.replace(hour=0, minute=0, second=0, microsecond=0))
    momentos = [
        datetime.fromisoformat(linha["momento"])
        for linha in conexao.execute(
            "SELECT momento FROM varreduras WHERE momento >= ? ORDER BY momento", (inicio_dia,)
        )
    ]
    total = 0
    for anterior, atual in zip(momentos, momentos[1:]):
        intervalo = (atual - anterior).total_seconds()
        if intervalo <= LACUNA_MAXIMA.total_seconds():
            total += intervalo
    return int(total)


def segundos_hoje(conexao, chave, agora_dt=None):
    """Soma o tempo que o aparelho ficou conectado desde a meia-noite de hoje."""
    agora_dt = agora_dt or datetime.now()
    inicio_dia = agora_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    total = 0
    for sessao in conexao.execute("SELECT inicio, fim FROM sessoes WHERE mac = ?", (chave,)):
        inicio = max(datetime.fromisoformat(sessao["inicio"]), inicio_dia)
        fim = datetime.fromisoformat(sessao["fim"]) if sessao["fim"] else agora_dt
        if fim > inicio:
            total += (fim - inicio).total_seconds()
    return int(total)


def resumo_aparelhos(conexao, agora_dt=None):
    """Um resumo por aparelho: se está conectado, desde quando e quanto tempo hoje."""
    agora_dt = agora_dt or datetime.now()
    resultado = []
    for disp in conexao.execute("SELECT * FROM dispositivos").fetchall():
        sessao = conexao.execute(
            "SELECT inicio FROM sessoes WHERE mac = ? AND fim IS NULL", (disp["mac"],)
        ).fetchone()
        desde = sessao["inicio"] if sessao else None
        segundos_atual = (agora_dt - datetime.fromisoformat(desde)).total_seconds() if desde else 0
        resultado.append(
            {
                "chave": disp["mac"],
                "ip": disp["ultimo_ip"],
                "fabricante": disp["fabricante"] or "",
                "nome_rede": disp["nome_rede"],
                "descoberto": disp["descoberto"],
                "primeiro_visto": disp["primeiro_visto"],
                "ultimo_visto": disp["ultimo_visto"],
                "conectado_desde": desde,
                "segundos_atual": segundos_atual,
                "segundos_hoje": segundos_hoje(conexao, disp["mac"], agora_dt),
            }
        )
    return resultado


def eventos_recentes(conexao, limite=8):
    return conexao.execute(
        "SELECT momento, tipo, mac, detalhe FROM eventos ORDER BY id DESC LIMIT ?", (limite,)
    ).fetchall()


# --- Referências de segurança (MAC do roteador, DNS, pontos de acesso conhecidos) ---
# Guardadas por rede (ex: pelo nome do Wi-Fi), na forma "nome|rede".

def referencias_da_rede(conexao, rede_id):
    sufixo = f"|{rede_id}"
    return {
        linha["chave"][: -len(sufixo)]: linha["valor"]
        for linha in conexao.execute("SELECT chave, valor FROM referencias")
        if linha["chave"].endswith(sufixo)
    }


def gravar_referencias(conexao, rede_id, itens, momento_dt=None):
    momento = _iso(momento_dt or datetime.now())
    for nome, valor in itens.items():
        conexao.execute(
            "INSERT OR REPLACE INTO referencias (chave, valor, atualizado) VALUES (?, ?, ?)",
            (f"{nome}|{rede_id}", valor, momento),
        )
    conexao.commit()


def apagar_referencias(conexao, rede_id):
    sufixo = f"|{rede_id}"
    cur = conexao.execute("SELECT chave FROM referencias")
    for linha in cur.fetchall():
        if linha["chave"].endswith(sufixo):
            conexao.execute("DELETE FROM referencias WHERE chave = ?", (linha["chave"],))
    conexao.commit()


def formatar_duracao(segundos):
    segundos = int(segundos)
    horas, resto = divmod(segundos, 3600)
    minutos, seg = divmod(resto, 60)
    if horas:
        return f"{horas}h {minutos}min"
    if minutos:
        return f"{minutos}min"
    return f"{seg}s"