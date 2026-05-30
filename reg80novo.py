import csv
import struct
import datetime
import pandas as pd
import streamlit as st

# --- 1. DICIONÁRIO DE QUALIFICADORES EM PORTUGUÊS (EVENTO 1 - IBM RACF) ---
MAPA_QUALIFICADORES_EVT1_PT = {
    0: "Sucesso na iniciação (Acesso concedido)",
    1: "Senha inválida",
    2: "Grupo inválido",
    3: "OIDCARD inválido",
    4: "Terminal ou console inválido",
    5: "Aplicação inválida",
    6: "Usuário revogado tentando acesso",
    7: "ID de usuário automaticamente revogado por excesso de tentativas de senha/frase",
    8: "Encerramento com sucesso (Logoff bem-sucedido)",
    9: "ID de usuário não definido no sistema",
    10: "Autoridade de Security Label insuficiente",
    11: "Não autorizado para este Security Label",
    12: "Iniciação RACINIT com sucesso",
    13: "Exclusão RACINIT com sucesso",
    14: "O sistema agora exige maior nível de autoridade",
    15: "Entrada de Job remoto - Job não autorizado",
    16: "A classe SURROGAT está inativa",
    17: "Submissor do Job não autorizado pelo usuário",
    18: "Submissor do Job não autorizado para o Security Label",
    19: "Usuário não autorizado para este Job",
    20: "AVISO - Autoridade de Security Label insuficiente",
    21: "AVISO - Security Label ausente no usuário, job ou perfil",
    22: "AVISO - Não autorizado para o Security Label",
    23: "Security Labels incompatíveis",
    24: "AVISO - Security Labels incompatíveis",
    25: "A senha atual (PASSWORD) expirou",
    26: "Nova senha (PASSWORD) inválida",
    27: "Falha na verificação por rotina de instalação local",
    28: "O acesso ao grupo foi revogado",
    29: "OIDCARD é obrigatório",
    30: "Entrada de Job via rede (NJE) - Job não autorizado",
    31: "Aviso - Usuário desconhecido propagado de nó confiável",
    32: "Iniciação realizada com sucesso utilizando PassTicket",
    33: "Tentativa de reutilização (Replay) de PassTicket",
    34: "Security Label do cliente não é equivalente ao do servidor",
    35: "Usuário automaticamente revogado por inatividade",
    36: "Frase de senha (Password Phrase) inválida",
    37: "Nova frase de senha inválida",
    38: "A frase de senha atual expirou",
    39: "Nenhum ID de usuário RACF encontrado para a identidade distribuída",
    40: "Autenticação Multifator (MFA) realizada com sucesso",
    41: "Falha na Autenticação Multifator (MFA)",
    42: "Falha na autenticação: nenhuma decisão MFA pôde ser tomada (MFA NOPWFALLBACK ativo)"
}

def decodificar_qualificador_ibm(evt: int, evq: int) -> str:
    """Traduz o qualificador operacional baseado nas tabelas e máscaras de bits IBM RACF."""
    if evt == 1:
        return MAPA_QUALIFICADORES_EVT1_PT.get(evq, f"0x{evq:02X}")

    if evt in (2, 24):
        if evq == 0xE2:
            return "ALTER (Privilégio Máximo) via FASTAUTH com gravação de estatísticas desativada (NOSTAT)"
        elif evq == 0x82:
            return "ALTER (Privilégio Máximo) via FASTAUTH com gravação de estatísticas ativada"
        elif evq == 0xA2:
            return "UPDATE (Alteração / Modificação) via FASTAUTH com gravação de estatísticas desativada (NOSTAT)"
        elif evq == 0xC2:
            return "CONTROL (Controle VSAM) via FASTAUTH com gravação de estatísticas desativada (NOSTAT)"
        elif evq & 0x01 or evq == 1:
            return "READ (Leitura / Execução)"
        elif evq & 0x02 or evq == 2:
            return "UPDATE (Alteração / Modificação de Escrita)"
        elif evq & 0x04:
            return "CONTROL (Controle Estrutural de Permissões VSAM)"
        elif evq & 0x08 or evq == 4:
            return "ALTER (Privilégio Máximo / Criação ou Exclusão total)"
        elif evq == 0:
            return "READ (Acesso Padrão Concedido)"
            
    return f"0x{evq:02X}"

# --- 2. FUNÇÕES DE DECODIFICAÇÃO MAINFRAME ---

def decodificar_ebcdic(b: bytes) -> str:
    if not b:
        return ""
    try:
        texto = b.decode("cp500").strip()
        texto_limpo = "".join(c for c in texto if c.isalnum() or c in "._-$@# ")
        if texto_limpo and not texto_limpo.isspace():
            return texto_limpo
        return b.hex().upper()
    except Exception:
        return b.hex().upper()

def decodificar_packed_decimal(b: bytes) -> str:
    if not b or len(b) < 4:
        return ""
    hex_str = b.hex().upper()
    try:
        seculo_digito = hex_str[0:2]
        ano_digitos = hex_str[2:4]
        dia_digitos = hex_str[4:7]
        
        prefixo_ano = 2000 if seculo_digito in ("01", "1", "2") else 1900
        ano_final = prefixo_ano + int(ano_digitos)
        dias_julianos = int(dia_digitos)
        
        if dias_julianos < 1 or dias_julianos > 366:
            return hex_str
            
        data_base = datetime.date(ano_final, 1, 1)
        data_civil = data_base + datetime.timedelta(days=dias_julianos - 1)
        return data_civil.strftime("%d/%m/%Y")
    except Exception:
        return hex_str

def map_single_byte(b: bytes, index: int) -> int:
    if index < len(b):
        return b[index]
    return 0

def mapear_layout_smf80_puro(registro: bytes) -> dict:
    if len(registro) < 80:
        return None
    try:
        smf80len = struct.unpack(">H", registro[0:2])[0]
        smf80seg = struct.unpack(">H", registro[2:4])[0]
        smf80flg_raw = map_single_byte(registro, 4)
        smf80rty = map_single_byte(registro, 5)
        
        smf80tme = struct.unpack(">I", registro[6:10])[0]
        segundos_totais = smf80tme // 100
        
        horas = segundos_totais // 3600
        minutos = (segundos_totais % 3600) // 60
        segundos = segundos_totais % 60
        
        if horas >= 24 or minutos >= 60 or segundos >= 60:
            return None
            
        tempo_formatado = f"{horas:02d}:{minutos:02d}:{segundos:02d}"

        evt_code = map_single_byte(registro, 22)
        evq_code = map_single_byte(registro, 23)
        err_byte = map_single_byte(registro, 44)
        err_hex = f"0x{err_byte:02X}"

        hex_evento = f"0x{evt_code:02X}"
        operacao_detalhe = decodificar_qualificador_ibm(int(evt_code), int(evq_code))
        status_final = "✅" if evq_code == 0 else "❌"

        dados = {
            "SMF80LEN": int(smf80len),
            "SMF80SEG": int(smf80seg),
            "SMF80FLG": f"0x{smf80flg_raw:02X}",
            "SMF80RTY": int(smf80rty),
            "HORA_EVENTO": str(tempo_formatado),
            "DATA_EVENTO": str(decodificar_packed_decimal(registro[10:14])),
            "SMF80SID": str(decodificar_ebcdic(registro[14:18])),
            "SMF80PID": str(decodificar_ebcdic(registro[18:22])),
            
            "AÇÃO_AUDITADA": hex_evento,
            "DETALHE_DA_OPERAÇÃO": operacao_detalhe,
            "STATUS_SEGURANÇA": status_final,
            
            "SMF80USR": str(decodificar_ebcdic(registro[24:32])),
            "SMF80GRP": str(decodificar_ebcdic(registro[32:40])),
            "SMF80REL": int(struct.unpack(">H", registro[40:42])[0]), 
            "SMF80CNT": int(struct.unpack(">H", registro[42:44])[0]), 
            "SMF80ATH": f"0x{map_single_byte(registro, 44):02X}",
            "SMF80REA": f"0x{map_single_byte(registro, 45):02X}",
            "SMF80TLV": int(map_single_byte(registro, 46)),
            "SMF80ERR": err_hex,
            "SMF80TRM": str(decodificar_ebcdic(registro[47:55])),
            "SMF80JBN": str(decodificar_ebcdic(registro[55:63])),
            "SMF80RST": int(struct.unpack(">I", registro[63:67])[0]), 
            "SMF80RSD": str(decodificar_packed_decimal(registro[67:71])),
            "SMF80UID": str(decodificar_ebcdic(registro[71:79])),
            "RAW_TME_KEY": smf80tme
        }
        return dados
    except Exception:
        return None

# --- 3. INTERFACE WEB PARALELA E BLINDADA ---

st.set_page_config(page_title="SMF 80 RACF Expert Auditor", layout="wide")
st.title("📊 Auditor Avançado RACF - Registro SMF Tipo 80")
st.write("Varredura robusta por assinaturas com consolidação e agrupamento avançado de segmentos irmãos.")

arquivo_carregado = st.file_uploader(
    "Selecione o arquivo de log EBCDIC (.bin)", type=["bin"]
)

if arquivo_carregado is not None:
    conteudo_bytes = arquivo_carregado.read()
    total_bytes = len(conteudo_bytes)
    
    indices_assinaturas = [idx for idx in range(total_bytes) if conteudo_bytes[idx] == 80]
    agrupador_eventos = {}
    
    for idx in indices_assinaturas:
        if idx - 5 >= 0:
            fim_fatia = min(idx + 123, total_bytes)
            fatia_util = conteudo_bytes[idx - 5 : fim_fatia]
            try:
                dados = mapear_layout_smf80_puro(fatia_util)
                if dados and dados["SMF80RTY"] == 80:
                    id_evento = f"{dados['RAW_TME_KEY']}_{dados['SMF80USR']}_{dados['SMF80JBN']}"
                    
                    if id_evento not in agrupador_eventos:
                        agrupador_eventos[id_evento] = dados
                    else:
                        if dados["SMF80SEG"] > agrupador_eventos[id_evento]["SMF80SEG"]:
                            agrupador_eventos[id_evento]["SMF80SEG"] = dados["SMF80SEG"]
            except Exception:
                pass

    registro_mapeado = list(agrupador_eventos.values())
    for item in registro_mapeado:
        item.pop("RAW_TME_KEY", None)

    quantidade_lida = len(registro_mapeado)
    st.metric(label="Eventos Consolidados e Higienizados", value=quantidade_lida)

    # EXIBIÇÃO LINEAR CRÍTICA: Sem estruturas condicionais aninhadas que quebrem indentação
    df_completo = pd.DataFrame(registro_mapeado)
    st.success("🎉 Varredura concluída! Todos os segmentos irmãos foram agrupados e as máscaras de bits detalhadas.")
    st.dataframe(df_completo.astype(str), use_container_width=True)
