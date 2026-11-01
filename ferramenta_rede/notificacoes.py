"""
Notificações: aviso no Windows (winotify) e, se você configurar, no Telegram.
O token do bot fica só em 'configuracao_local.json' (ignorado pelo Git).
"""
import getpass
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ARQUIVO_CONFIG = Path(__file__).resolve().parent / "configuracao_local.json"
NOME_APP = "Dashboard de Segurança"


def carregar_config():
    try:
        with open(ARQUIVO_CONFIG, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
        return dados if isinstance(dados, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def salvar_config(config):
    with open(ARQUIVO_CONFIG, "w", encoding="utf-8") as arquivo:
        json.dump(config, arquivo, indent=2)


def notificar_windows(titulo, mensagem):
    try:
        from winotify import Notification

        Notification(app_id=NOME_APP, title=titulo, msg=mensagem[:250], duration="short").show()
        return True
    except Exception:
        return False


def notificar_telegram(titulo, mensagem):
    config = carregar_config()
    token, chat = config.get("telegram_token"), config.get("telegram_chat_id")
    if not token or not chat:
        return False
    dados = urllib.parse.urlencode({"chat_id": chat, "text": f"{titulo}\n{mensagem}"[:4000]}).encode()
    try:
        with urllib.request.urlopen(
            f"https://api.telegram.org/bot{token}/sendMessage", data=dados, timeout=10
        ) as resposta:
            return resposta.status == 200
    except Exception:
        return False


def notificar(titulo, mensagem):
    """Tenta todos os canais e devolve a lista dos que funcionaram. Nunca levanta erro."""
    canais = []
    if notificar_windows(titulo, mensagem):
        canais.append("Windows")
    if notificar_telegram(titulo, mensagem):
        canais.append("Telegram")
    return canais


def configurar_telegram():
    print("=== Configurar alertas no Telegram ===")
    print("1) No Telegram, abra a conversa com @BotFather, envie /newbot e siga as instruções.")
    print("2) Copie o token que ele mostrar (parece com 123456:ABC-DEF...).")
    print("3) Abra o SEU bot novo no Telegram e envie qualquer mensagem para ele (ex: oi).\n")
    token = getpass.getpass("Cole o token aqui (não aparece nada na tela ao colar; é normal) e aperte Enter: ").strip()
    if not token:
        print("Nenhum token informado. Nada foi salvo.")
        return

    try:
        with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/getUpdates", timeout=10) as resposta:
            dados = json.load(resposta)
    except Exception as erro:
        print(f"Não consegui falar com o Telegram ({type(erro).__name__}). Confira o token e a internet.")
        return

    chats = [u["message"]["chat"]["id"] for u in dados.get("result", []) if "message" in u]
    if not chats:
        print("O bot ainda não recebeu nenhuma mensagem. Envie 'oi' para ele no Telegram e rode de novo.")
        return

    config = carregar_config()
    config["telegram_token"] = token
    config["telegram_chat_id"] = chats[-1]
    salvar_config(config)
    print("Configurado! Enviando mensagem de teste...")
    print("Teste enviado." if notificar_telegram(NOME_APP, "Alertas no Telegram funcionando.") else "O teste falhou.")


if __name__ == "__main__":
    if "--configurar-telegram" in sys.argv:
        configurar_telegram()
    elif "--testar" in sys.argv:
        canais = notificar(NOME_APP, "Teste de notificação: se você está vendo isto, funcionou.")
        print(f"Canais que funcionaram: {', '.join(canais) if canais else 'nenhum'}")
        if not canais:
            print("Dica: instale o aviso do Windows com  pip install winotify  e/ou configure o Telegram.")
    else:
        print("Uso: python ferramenta_rede\\notificacoes.py --testar | --configurar-telegram")