# Dashboard de Segurança

Aplicativo desktop para Windows, em Python, para monitorar e auditar a segurança
da própria rede doméstica. Criado como projeto de portfólio.

## O que o projeto faz

- **Varredura da rede**: identifica os aparelhos conectados (IP, MAC, fabricante,
  latência, tempo de conexão) combinando ping sweep com leitura da tabela ARP do
  Windows via PowerShell (`Get-NetNeighbor`), contornando a limitação do envio de
  ARP cru pelo Scapy no Windows.
- **Reconhecimento de MAC privado/aleatório**: identifica quando um aparelho está
  usando endereço MAC rotativo (padrão em iOS e Android modernos).
- **Histórico de presença**: grava sessões de conexão em SQLite, com tolerância a
  falhas de ping (um aparelho só é considerado ausente depois de 3 varreduras sem
  resposta), evitando falsos alertas de "entrou/saiu" quando um celular está com a
  tela apagada.
- **Alertas de segurança**: detecta mudança no MAC do roteador, o mesmo MAC
  aparecendo em mais de um IP (indício de ARP spoofing) e mudança nos servidores
  DNS da rede.
- **Verificação do Wi-Fi**: lê o protocolo de segurança da rede (WPA2/WPA3) e
  alerta sobre nome de rede duplicado (possível ponto de acesso falso).
- **Verificação de portas**: varre os aparelhos da rede em busca de serviços de
  risco (Telnet, SMB, RDP, etc.), com palpite do tipo de aparelho pelas portas
  abertas.
- **Nota de saúde da rede**: combina as checagens de Wi-Fi e de portas numa nota
  de 0 a 100, com recomendações.
- **Descoberta de nomes**: tenta identificar nomes e modelos de aparelhos via
  mDNS e SSDP/UPnP.
- **Notificações**: avisos nativos do Windows (e, opcionalmente, Telegram) quando
  surge um aparelho novo e desconhecido ou um alerta de segurança.
- **Interface gráfica** (PySide6): reúne tudo em uma janela com tabela de
  dispositivos (desconhecidos destacados), aba de alertas/eventos e aba de saúde
  da rede, com varredura automática em intervalo configurável.

## Limitações (por design)

Este projeto só monitora a própria rede, a partir de um único PC Windows, sem
acesso ao roteador. Isso impõe limites conscientes:

- **Não identifica o modelo exato do celular conectado.** Sem acesso ao painel do
  roteador (que mostraria o hostname via DHCP) ou a um adaptador Wi-Fi com modo
  monitor (para capturar probe requests), a identificação de modelo específico
  não é confiável. O projeto reconhece o fabricante pelo prefixo do MAC quando
  possível, e o tipo de dispositivo (ex: iPhone/iPad) pela porta de serviço
  aberta, quando houver uma.
- **Não mede o consumo de dados dos outros aparelhos**, só do próprio PC. Isso
  exigiria acesso ao roteador.
- **A cobertura do histórico é limitada ao tempo em que o monitor está rodando**,
  já que não há um aparelho ligado 24 horas na rede.
- **A nota de saúde não testa a força da senha do Wi-Fi.** Esse teste fica a
  cargo do módulo de Auditoria WiFi (ver "Próximos passos").

Essas decisões foram deliberadas: o projeto prioriza dados confiáveis e
verificáveis sobre estimativas pouco confiáveis.

## Arquitetura


Os módulos de rede são independentes entre si: uma falha num módulo opcional
(Wi-Fi, descoberta, notificações) não derruba o monitoramento.

## Como rodar

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python dashboard.py
```

## Próximos passos

- Módulo de Auditoria WiFi (teste de força da senha da própria rede, com Scapy e
  aircrack-ng), que exige um adaptador Wi-Fi USB com suporte a modo monitor.
- Integração com o painel do roteador, quando o acesso for recuperado, para
  nomes automáticos de aparelhos e consumo de dados por aparelho.
- Alerta de "horário normal" por aparelho, após alguns dias de histórico
  acumulado.
- Empacotamento como executável (PyInstaller).

## Aviso

Este projeto monitora e audita **apenas a rede do próprio autor**. Não realiza
sniffing, ARP spoofing nem qualquer ataque contra redes ou aparelhos de
terceiros.