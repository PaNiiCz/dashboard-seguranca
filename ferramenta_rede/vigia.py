"""vigia.py - observa o consumo do PROPRIO programa e da MAQUINA como um todo,
e avisa se algum dos dois ficar alto por tempo demais.

Dois conjuntos de limites, de propósito separados:
- "própria": só o processo do Dashboard. Se passar, o problema é o programa.
- "sistema": o PC inteiro. Se passar, o PC está pesado, mas pode não ser o Dashboard.
"""
import os
import time

import psutil

LIMITE_RAM_PROPRIA_MB = 300
LIMITE_CPU_PROPRIA_PCT = 40

LIMITE_RAM_SISTEMA_PCT = 90
LIMITE_CPU_SISTEMA_PCT = 90
LIMITE_DISCO_PCT = 95

SEGUNDOS_PARA_ALERTAR = 60  # só alerta se o problema persistir por esse tempo (evita picos normais)


class Vigia:
    def __init__(self):
        self.processo = psutil.Process(os.getpid())
        self.processo.cpu_percent()  # "aquece" a medição (a primeira leitura sempre vem 0.0)
        self.historico_cpu_propria = []
        self.acima_desde = {}

    def amostra(self):
        """Uma leitura pontual. Devolve (dados, alertas)."""
        cpu_propria = self.processo.cpu_percent()
        ram_propria_mb = self.processo.memory_info().rss / (1024 * 1024)

        cpu_sistema = psutil.cpu_percent()
        ram_sistema = psutil.virtual_memory()
        unidade = os.path.splitdrive(os.getcwd())[0] + "\\"
        disco = psutil.disk_usage(unidade)

        self.historico_cpu_propria = (self.historico_cpu_propria + [cpu_propria])[-5:]
        media_cpu_propria = sum(self.historico_cpu_propria) / len(self.historico_cpu_propria)

        dados = {
            "cpu_propria_pct": cpu_propria,
            "cpu_propria_media_pct": media_cpu_propria,
            "ram_propria_mb": ram_propria_mb,
            "cpu_sistema_pct": cpu_sistema,
            "ram_sistema_pct": ram_sistema.percent,
            "disco_pct": disco.percent,
        }

        alertas = []
        agora = time.time()

        def checar(chave, condicao, mensagem):
            if condicao:
                inicio = self.acima_desde.setdefault(chave, agora)
                if agora - inicio >= SEGUNDOS_PARA_ALERTAR:
                    alertas.append((chave, mensagem))
            else:
                self.acima_desde.pop(chave, None)

        checar(
            "ram_propria", ram_propria_mb > LIMITE_RAM_PROPRIA_MB,
            f"O Dashboard está usando {ram_propria_mb:.0f} MB de memória "
            f"(acima do esperado, {LIMITE_RAM_PROPRIA_MB} MB). Considere reiniciar o programa.",
        )
        checar(
            "cpu_propria", media_cpu_propria > LIMITE_CPU_PROPRIA_PCT,
            f"O Dashboard está usando {media_cpu_propria:.0f}% de CPU de forma sustentada.",
        )
        checar(
            "ram_sistema", ram_sistema.percent > LIMITE_RAM_SISTEMA_PCT,
            f"A memória do PC está em {ram_sistema.percent:.0f}% de uso "
            "(pode não ser o Dashboard - veja o Gerenciador de Tarefas).",
        )
        checar(
            "cpu_sistema", cpu_sistema > LIMITE_CPU_SISTEMA_PCT,
            f"O processador do PC está em {cpu_sistema:.0f}% de uso "
            "(pode não ser o Dashboard - veja o Gerenciador de Tarefas).",
        )
        checar(
            "disco", disco.percent > LIMITE_DISCO_PCT,
            f"O disco está com {disco.percent:.0f}% de uso (quase cheio).",
        )

        return dados, alertas