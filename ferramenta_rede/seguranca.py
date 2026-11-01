"""
Checagens de segurança da sua própria rede. As funções aqui só recebem dados
(já coletados) e devolvem alertas, então podem ser testadas sem rede nenhuma.
"""


def verificar(referencias, dispositivos, gateway_ip, dns):
    """
    referencias: o que já foi guardado para esta rede (ex: {'gateway_mac': '...', 'dns': '...'}).
    Devolve (alertas, a_gravar):
      - alertas: lista de {'chave', 'nivel', 'mensagem'}
      - a_gravar: referências novas aprendidas agora (primeira vez que a rede é vista)
    A primeira vez que uma rede é vista vira a "linha de base" (assume-se rede limpa).
    """
    alertas = []
    a_gravar = {}

    # 1) O MAC do roteador mudou? (sinal clássico de ARP spoofing)
    if gateway_ip:
        roteador = next(
            (d for d in dispositivos if d["ip"] == gateway_ip and d.get("mac") not in (None, "—")),
            None,
        )
        if roteador:
            antigo = referencias.get("gateway_mac")
            if antigo is None:
                a_gravar["gateway_mac"] = roteador["mac"]
            elif antigo != roteador["mac"]:
                alertas.append(
                    {
                        "chave": "gateway_mac",
                        "nivel": "alto",
                        "mensagem": (
                            f"O MAC do roteador ({gateway_ip}) mudou de {antigo} para "
                            f"{roteador['mac']}. Pode ser alguém se passando pelo roteador "
                            "(ARP spoofing) ou a troca/reset do equipamento."
                        ),
                    }
                )

    # 2) O mesmo MAC em vários IPs?
    por_mac = {}
    for d in dispositivos:
        mac = d.get("mac")
        if mac and mac != "—":
            por_mac.setdefault(mac, []).append(d["ip"])
    for mac, ips in por_mac.items():
        if len(ips) > 1:
            alertas.append(
                {
                    "chave": f"mac_repetido:{mac}",
                    "nivel": "alto" if gateway_ip in ips else "medio",
                    "mensagem": (
                        f"O mesmo MAC ({mac}) aparece em vários IPs: {', '.join(sorted(ips))}. "
                        "É um sinal de ARP spoofing, mas também pode ser um repetidor ou "
                        "equipamento que responde por mais de um IP."
                    ),
                }
            )

    # 3) Os servidores DNS mudaram? (DNS adulterado redireciona sites)
    if dns:
        atual = ",".join(sorted(dns))
        antigo = referencias.get("dns")
        if antigo is None:
            a_gravar["dns"] = atual
        elif antigo != atual:
            alertas.append(
                {
                    "chave": "dns",
                    "nivel": "alto",
                    "mensagem": (
                        f"Os servidores DNS desta rede mudaram de {antigo} para {atual}. "
                        "Se você não mudou nada, confira o roteador."
                    ),
                }
            )

    return alertas, a_gravar