"""tela_rede.py - janela principal do Dashboard de Segurança (PySide6)."""
import threading
from datetime import datetime

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QHBoxLayout, QHeaderView, QLabel, QMainWindow,
    QPlainTextEdit, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem,
    QTabWidget, QVBoxLayout, QWidget,
)

import nucleo
import painel
import saude
import uso_rede
import velocidade
import vigia

COR_STATUS = {
    "saudável": "#2e7d32", "atenção": "#e65100", "ruim": "#c62828",
    "sem ping": "#1565c0", "ausente": "#757575", "offline": "#757575",
}


def duracao(seg):
    seg = int(seg or 0)
    if seg < 60:
        return f"{seg}s"
    minutos = seg // 60
    if minutos < 60:
        return f"{minutos}min"
    horas, minutos = divmod(minutos, 60)
    if horas < 24:
        return f"{horas}h {minutos:02d}min"
    dias, horas = divmod(horas, 24)
    return f"{dias}d {horas}h"


def hora(iso, formato="%d/%m %H:%M:%S"):
    try:
        return datetime.fromisoformat(iso).strftime(formato)
    except Exception:
        return str(iso or "")


def ordem_ip(ip):
    try:
        return tuple(int(n) for n in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def celula(texto, fundo=None, frente=None, negrito=False):
    item = QTableWidgetItem(str(texto))
    if fundo:
        item.setBackground(QBrush(QColor(fundo)))
    if frente:
        item.setForeground(QBrush(QColor(frente)))
    if negrito:
        fonte = QFont()
        fonte.setBold(True)
        item.setFont(fonte)
    return item


class Ponte(QObject):
    """Leva o resultado das threads de segundo plano para a janela."""
    scan_ok = Signal(object)
    scan_erro = Signal(str)
    saude_ok = Signal(object)
    saude_erro = Signal(str)
    velocidade_ok = Signal(object)
    velocidade_erro = Signal(str)
    processos_ok = Signal(object)
    processos_erro = Signal(str)


class JanelaPrincipal(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dashboard de Segurança")
        self.resize(1100, 640)
        self.nucleo = nucleo.Nucleo()
        self.ocupado = False

        self.vigia = vigia.Vigia()
        self.vigia_notificados = set()
        self.label_recursos = QLabel("")
        self.statusBar().addPermanentWidget(self.label_recursos)
        self.timer_vigia = QTimer(self)
        self.timer_vigia.timeout.connect(self._checar_recursos)
        self.timer_vigia.start(15000)

        self.ponte = Ponte()
        self.ponte.scan_ok.connect(self._scan_pronto)
        self.ponte.scan_erro.connect(self._scan_erro)
        self.ponte.saude_ok.connect(self._saude_pronta)
        self.ponte.saude_erro.connect(self._saude_erro)
        self.ponte.velocidade_ok.connect(self._velocidade_pronta)
        self.ponte.velocidade_erro.connect(self._velocidade_erro)
        self.ponte.processos_ok.connect(self._processos_prontos)
        self.ponte.processos_erro.connect(self._processos_erro)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Barra de controles
        barra = QHBoxLayout()
        self.btn_scan = QPushButton("Escanear agora")
        self.btn_scan.clicked.connect(self.escanear)
        self.auto = QCheckBox("Monitorar automaticamente a cada")
        self.auto.toggled.connect(self._auto_mudou)
        self.intervalo = QSpinBox()
        self.intervalo.setRange(10, 300)
        self.intervalo.setValue(60)
        self.intervalo.setSuffix(" s")
        barra.addWidget(self.btn_scan)
        barra.addWidget(self.auto)
        barra.addWidget(self.intervalo)
        barra.addStretch()
        layout.addLayout(barra)

        self.resumo = QLabel("Aguardando a primeira varredura...")
        layout.addWidget(self.resumo)

        abas = QTabWidget()
        layout.addWidget(abas)

        # Aba 1: dispositivos
        self.colunas = ["Dispositivo", "IP", "Fabricante / descoberto",
                        "Conectado há", "Hoje", "Latência", "Status"]
        self.tabela = QTableWidget(0, len(self.colunas))
        self.tabela.setHorizontalHeaderLabels(self.colunas)
        self.tabela.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tabela.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tabela.verticalHeader().setVisible(False)
        self.tabela.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tabela.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        abas.addTab(self.tabela, "Dispositivos")

        # Aba 2: alertas e eventos
        aba_alertas = QWidget()
        lay_alertas = QVBoxLayout(aba_alertas)
        lay_alertas.addWidget(QLabel("Alertas de segurança"))
        self.texto_alertas = QPlainTextEdit()
        self.texto_alertas.setReadOnly(True)
        self.texto_alertas.setMaximumHeight(140)
        lay_alertas.addWidget(self.texto_alertas)
        lay_alertas.addWidget(QLabel("Últimos eventos"))
        self.tabela_eventos = QTableWidget(0, 4)
        self.tabela_eventos.setHorizontalHeaderLabels(["Quando", "Tipo", "Quem", "Detalhe"])
        self.tabela_eventos.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tabela_eventos.verticalHeader().setVisible(False)
        self.tabela_eventos.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tabela_eventos.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        lay_alertas.addWidget(self.tabela_eventos)
        abas.addTab(aba_alertas, "Alertas e eventos")

        # Aba 3: saúde da rede
        aba_saude = QWidget()
        lay_saude = QVBoxLayout(aba_saude)
        self.btn_saude = QPushButton("Verificar saúde da rede")
        self.btn_saude.clicked.connect(self.verificar_saude)
        self.nota = QLabel("Nota: —")
        fonte = QFont()
        fonte.setPointSize(26)
        fonte.setBold(True)
        self.nota.setFont(fonte)
        self.texto_saude = QPlainTextEdit()
        self.texto_saude.setReadOnly(True)
        self.texto_saude.setPlainText("Clique em \"Verificar saúde da rede\" (leva uns 20 segundos).")
        lay_saude.addWidget(self.btn_saude)
        lay_saude.addWidget(self.nota)
        lay_saude.addWidget(self.texto_saude)
        abas.addTab(aba_saude, "Saúde da rede")

        # Aba 4: internet (velocidade e uso aproximado por processo)
        aba_internet = QWidget()
        lay_internet = QVBoxLayout(aba_internet)

        linha_vel = QHBoxLayout()
        self.btn_velocidade = QPushButton("Testar velocidade agora (usa dados reais, ~20s)")
        self.btn_velocidade.clicked.connect(self.testar_velocidade)
        linha_vel.addWidget(self.btn_velocidade)
        linha_vel.addStretch()
        lay_internet.addLayout(linha_vel)

        self.label_velocidade = QLabel("Download: —    Upload: —    Ping: —")
        fonte_vel = QFont()
        fonte_vel.setPointSize(16)
        fonte_vel.setBold(True)
        self.label_velocidade.setFont(fonte_vel)
        lay_internet.addWidget(self.label_velocidade)

        self.texto_velocidade = QPlainTextEdit()
        self.texto_velocidade.setReadOnly(True)
        self.texto_velocidade.setMaximumHeight(100)
        self.texto_velocidade.setPlainText("Clique no botão acima para medir.")
        lay_internet.addWidget(self.texto_velocidade)

        lay_internet.addWidget(QLabel(
            "Processos mais ativos agora (por nº de conexões abertas - aproximação, não é "
            "medição exata de MB; Windows não expõe isso sem driver de captura):"
        ))
        linha_proc = QHBoxLayout()
        self.btn_processos = QPushButton("Atualizar lista")
        self.btn_processos.clicked.connect(self.atualizar_processos)
        linha_proc.addWidget(self.btn_processos)
        linha_proc.addStretch()
        lay_internet.addLayout(linha_proc)

        self.tabela_processos = QTableWidget(0, 2)
        self.tabela_processos.setHorizontalHeaderLabels(["Processo", "Conexões ativas"])
        self.tabela_processos.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tabela_processos.verticalHeader().setVisible(False)
        self.tabela_processos.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay_internet.addWidget(self.tabela_processos)

        abas.addTab(aba_internet, "Internet")

        self.statusBar().showMessage("Pronto.")
        QTimer.singleShot(300, self.escanear)

    # ---------- varredura ----------
    def escanear(self):
        if self.ocupado:
            return
        self.ocupado = True
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("Escaneando...")
        self.statusBar().showMessage("Escaneando a rede (pode levar de 15 a 40 segundos)...")
        threading.Thread(target=self._varrer_thread, daemon=True).start()

    def _varrer_thread(self):
        try:
            self.ponte.scan_ok.emit(self.nucleo.varrer())
        except Exception as erro:
            self.ponte.scan_erro.emit(f"{type(erro).__name__}: {erro}")

    def _scan_pronto(self, r):
        self._preencher_dispositivos(r)
        self._preencher_alertas(r)
        self._preencher_eventos(r)
        self.statusBar().showMessage(
            f"Última varredura: {datetime.now().strftime('%H:%M:%S')}"
            + ("  |  primeira varredura: aparelhos atuais guardados como ponto de partida"
               if r["primeira_vez"] else "")
        )
        self._fim_varredura()

    def _scan_erro(self, mensagem):
        self.statusBar().showMessage(f"Erro na varredura: {mensagem}")
        self._fim_varredura()

    def _fim_varredura(self):
        self.ocupado = False
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("Escanear agora")
        if self.auto.isChecked():
            QTimer.singleShot(self.intervalo.value() * 1000, self._escanear_se_auto)

    def _escanear_se_auto(self):
        if self.auto.isChecked() and not self.ocupado:
            self.escanear()

    def _auto_mudou(self, ligado):
        if ligado and not self.ocupado:
            self.escanear()

    # ---------- preenchimento ----------
    def _preencher_dispositivos(self, r):
        vivos = {painel.chave_de(d): d for d in r["dispositivos"]}
        conhecidos = r["conhecidos"]
        itens = sorted(r["resumo"], key=lambda i: ordem_ip(i.get("ip", "")))
        self.tabela.setRowCount(len(itens))
        conectados = desconhecidos = 0

        for linha, item in enumerate(itens):
            chave = item["chave"]
            d = vivos.get(chave)
            ausente = d is None or d.get("status") == "offline"
            conhecido = chave == "este-pc" or chave in conhecidos
            alerta = (not conhecido) and (not ausente)
            fundo = "#ffcdd2" if alerta else None
            frente = "#000000" if alerta else ("#757575" if ausente else None)

            if not ausente:
                conectados += 1
            if alerta:
                desconhecidos += 1

            status = "ausente" if ausente else d.get("status", "")
            if ausente:
                conectado = "visto " + hora(item.get("ultimo_visto"), "%d/%m %H:%M")
            else:
                conectado = duracao(item.get("segundos_atual"))
            latencia = "—"
            if d and d.get("latencia_ms") is not None:
                latencia = f"{d['latencia_ms']:.0f} ms"

            valores = [
                painel.nome_exibicao(chave, conhecidos),
                item.get("ip", ""),
                item.get("descoberto") or item.get("fabricante") or "",
                conectado,
                duracao(item.get("segundos_hoje")),
                latencia,
            ]
            for coluna, valor in enumerate(valores):
                self.tabela.setItem(linha, coluna, celula(valor, fundo, frente, negrito=alerta and coluna == 0))
            self.tabela.setItem(
                linha, 6,
                celula(status, fundo, COR_STATUS.get(status, frente), negrito=True),
            )

        self.resumo.setText(
            f"Rede {self.nucleo.faixa}   |   Conectados: {conectados}   |   "
            f"Desconhecidos: {desconhecidos}   |   Já vistos: {len(itens)}   |   "
            f"Monitorado hoje: {duracao(r['monitorado_hoje'])}"
        )

    def _preencher_alertas(self, r):
        linhas = [f"[!] {a['mensagem']}" for a in r["alertas"]]
        linhas += [f"[i] {a}" for a in r["avisos"]]
        if not linhas:
            linhas = ["Nenhum alerta (checados: MAC do roteador, MACs repetidos, DNS e rede Wi-Fi)."]
        self.texto_alertas.setPlainText("\n".join(linhas))

    def _preencher_eventos(self, r):
        conhecidos = r["conhecidos"]
        eventos = r["eventos"]
        self.tabela_eventos.setRowCount(len(eventos))
        for linha, e in enumerate(eventos):
            quando = ""
            for valor in e.values():
                if isinstance(valor, str) and len(valor) >= 19 and valor[4] == "-" and valor[10] in "T ":
                    quando = hora(valor)
                    break
            chave = e.get("chave", "")
            quem = "(este PC)" if chave == "este-pc" else conhecidos.get(chave, chave)
            for coluna, valor in enumerate([quando, e.get("tipo", ""), quem, e.get("detalhe", "")]):
                self.tabela_eventos.setItem(linha, coluna, QTableWidgetItem(str(valor)))

    # ---------- saúde da rede ----------
    def verificar_saude(self):
        self.btn_saude.setEnabled(False)
        self.btn_saude.setText("Verificando...")
        self.nota.setText("Nota: ...")
        self.texto_saude.setPlainText("Verificando Wi-Fi e portas dos aparelhos... aguarde.")
        threading.Thread(target=self._saude_thread, daemon=True).start()

    def _saude_thread(self):
        try:
            prefixo = ".".join(painel.FAIXA.split("/")[0].split(".")[:3])
            self.ponte.saude_ok.emit(saude.checar(prefixo))
        except Exception as erro:
            self.ponte.saude_erro.emit(f"{type(erro).__name__}: {erro}")

    def _saude_pronta(self, resultado):
        nota, itens = resultado
        marcas = {"ok": "[OK]", "aviso": "[!] ", "ruim": "[X] "}
        linhas = []
        for nivel, texto in itens:
            marca = "[i] " if "sem desconto" in texto else marcas[nivel]
            linhas.append(f"{marca} {texto}")
        linhas.append("")
        linhas.append("Limite: esta nota não testa a força da senha do Wi-Fi "
                      "(isso será feito no módulo Auditoria WiFi).")
        self.texto_saude.setPlainText("\n".join(linhas))
        cor = "#2e7d32" if nota >= 85 else ("#e65100" if nota >= 65 else "#c62828")
        self.nota.setText(f"Nota: {nota}/100")
        self.nota.setStyleSheet(f"color: {cor};")
        self._fim_saude()

    def _saude_erro(self, mensagem):
        self.texto_saude.setPlainText(f"Erro ao verificar: {mensagem}")
        self._fim_saude()

    def _fim_saude(self):
        self.btn_saude.setEnabled(True)
        self.btn_saude.setText("Verificar saúde da rede")

    # ---------- vigia de recursos ----------
    def _checar_recursos(self):
        dados, alertas = self.vigia.amostra()
        self.label_recursos.setText(
            f"App: {dados['ram_propria_mb']:.0f} MB / {dados['cpu_propria_media_pct']:.0f}% CPU"
            f"   |   PC: {dados['ram_sistema_pct']:.0f}% RAM, {dados['cpu_sistema_pct']:.0f}% CPU, "
            f"{dados['disco_pct']:.0f}% disco"
        )
        for chave, mensagem in alertas:
            if chave not in self.vigia_notificados:
                self.vigia_notificados.add(chave)
                painel.avisar("Alerta de desempenho", mensagem)
        self.vigia_notificados &= {chave for chave, _ in alertas}

    # ---------- teste de velocidade ----------
    def testar_velocidade(self):
        self.btn_velocidade.setEnabled(False)
        self.btn_velocidade.setText("Testando... (não feche o programa)")
        self.label_velocidade.setText("Download: ...    Upload: ...    Ping: ...")
        threading.Thread(target=self._velocidade_thread, daemon=True).start()

    def _velocidade_thread(self):
        try:
            conexao = velocidade.conectar()
            try:
                anteriores = velocidade.historico_recente(conexao, limite=10)
                resultado = velocidade.medir()
                avisos = velocidade.avaliar(resultado, anteriores)
                velocidade.registrar(conexao, resultado)
            finally:
                conexao.close()
            self.ponte.velocidade_ok.emit((resultado, avisos))
        except Exception as erro:
            self.ponte.velocidade_erro.emit(f"{type(erro).__name__}: {erro}")

    def _velocidade_pronta(self, dados):
        resultado, avisos = dados
        self.label_velocidade.setText(
            f"Download: {resultado['download_mbps']} Mbps    "
            f"Upload: {resultado['upload_mbps']} Mbps    "
            f"Ping: {resultado['ping_ms']} ms"
        )
        texto = f"Servidor: {resultado['servidor']}\n" + "\n".join(avisos)
        self.texto_velocidade.setPlainText(texto)
        self.btn_velocidade.setEnabled(True)
        self.btn_velocidade.setText("Testar velocidade agora (usa dados reais, ~20s)")

    def _velocidade_erro(self, mensagem):
        self.texto_velocidade.setPlainText(f"Erro: {mensagem}")
        self.btn_velocidade.setEnabled(True)
        self.btn_velocidade.setText("Testar velocidade agora (usa dados reais, ~20s)")

    # ---------- processos mais ativos ----------
    def atualizar_processos(self):
        self.btn_processos.setEnabled(False)
        self.btn_processos.setText("Atualizando...")
        threading.Thread(target=self._processos_thread, daemon=True).start()

    def _processos_thread(self):
        try:
            self.ponte.processos_ok.emit(uso_rede.processos_mais_ativos())
        except Exception as erro:
            self.ponte.processos_erro.emit(f"{type(erro).__name__}: {erro}")

    def _processos_prontos(self, lista):
        self.tabela_processos.setRowCount(len(lista))
        for linha, (nome, qtd) in enumerate(lista):
            self.tabela_processos.setItem(linha, 0, QTableWidgetItem(nome))
            self.tabela_processos.setItem(linha, 1, QTableWidgetItem(str(qtd)))
        self.btn_processos.setEnabled(True)
        self.btn_processos.setText("Atualizar lista")

    def _processos_erro(self, mensagem):
        self.tabela_processos.setRowCount(1)
        self.tabela_processos.setItem(0, 0, QTableWidgetItem(mensagem))
        self.tabela_processos.setItem(0, 1, QTableWidgetItem(""))
        self.btn_processos.setEnabled(True)
        self.btn_processos.setText("Atualizar lista")