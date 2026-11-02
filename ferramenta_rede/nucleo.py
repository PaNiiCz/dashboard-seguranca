"""nucleo.py - junta os motores numa única varredura que a interface chama.

Reaproveita as funções do painel.py. Não imprime nada: devolve um dicionário.
"""
import time

import descoberta
import historico
import monitor
import painel


class Nucleo:
    def __init__(self, faixa=None):
        self.faixa = faixa or painel.FAIXA
        self.descobertos = {}
        self.ultima_descoberta = 0.0
        self.notificados = set()

    def varrer(self):
        """Uma varredura completa. Abre e fecha a própria conexão com o banco
        (o SQLite não pode ser compartilhado entre threads)."""
        conexao = historico.conectar()
        try:
            dispositivos, rede = monitor.escanear_completo(self.faixa)
            conhecidos = monitor.carregar_conhecidos()

            meu = next((d for d in dispositivos if d.get("este_pc")), None)
            interface = monitor.alias_da_faixa(rede, self.faixa) or (
                painel.interface_do_ip(meu["ip"]) if meu else None
            )

            # Nomes e modelos (mDNS/SSDP): na primeira vez e depois de tempos em tempos
            if meu and time.time() - self.ultima_descoberta > painel.DESCOBERTA_A_CADA:
                try:
                    self.descobertos.update(descoberta.descobrir(meu["ip"]))
                except Exception:
                    pass
                self.ultima_descoberta = time.time()
            for d in dispositivos:
                d["descoberto"] = self.descobertos.get(d["ip"])

            eventos, primeira_vez = painel.registrar_varredura(conexao, dispositivos)

            try:
                alertas, avisos = painel.verificar_seguranca(conexao, rede, interface, dispositivos)
            except Exception as erro:
                alertas, avisos = [], [f"A checagem de segurança falhou ({type(erro).__name__}: {erro})"]

            # Notificações: cada alerta ou aparelho novo só uma vez por execução
            for alerta in alertas:
                chave = f"alerta:{alerta['chave']}"
                if chave not in self.notificados:
                    self.notificados.add(chave)
                    historico.registrar_evento(conexao, "alerta", "seguranca", alerta["mensagem"])
                    painel.avisar("Alerta de segurança na rede", alerta["mensagem"])
            for e in eventos:
                if e["tipo"] == "novo" and e["chave"] not in conhecidos:
                    chave = f"novo:{e['chave']}"
                    if chave not in self.notificados:
                        self.notificados.add(chave)
                        painel.avisar(
                            "Aparelho novo e desconhecido na rede",
                            f"IP {e['detalhe']}  |  MAC {e['chave']}",
                        )

            resumo = [dict(linha) for linha in historico.resumo_aparelhos(conexao)]
            recentes = [dict(linha) for linha in historico.eventos_recentes(conexao, 40)]
            return {
                "dispositivos": dispositivos,
                "conhecidos": conhecidos,
                "resumo": resumo,
                "eventos": recentes,
                "alertas": alertas,
                "avisos": avisos,
                "primeira_vez": primeira_vez,
                "monitorado_hoje": historico.cobertura_hoje(conexao),
                "momento": time.time(),
            }
        finally:
            conexao.close()