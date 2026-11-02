"""dashboard.py - ponto de entrada do Dashboard de Segurança.

Uso (na pasta raiz do projeto, com o venv ativo):  python dashboard.py
"""
import os
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
PASTA_REDE = RAIZ / "ferramenta_rede"

# Os arquivos de ferramenta_rede guardam o banco e o inventário na própria pasta,
# então trabalhamos a partir dela (igual aos testes feitos pelo terminal).
os.chdir(PASTA_REDE)
sys.path.insert(0, str(PASTA_REDE))
sys.path.insert(0, str(RAIZ))

from PySide6.QtWidgets import QApplication  # noqa: E402

from ui.tela_rede import JanelaPrincipal  # noqa: E402


def main():
    app = QApplication(sys.argv)
    janela = JanelaPrincipal()
    janela.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()