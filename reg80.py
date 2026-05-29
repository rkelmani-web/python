import csv
import struct
import pandas as pd
import streamlit as st

# --- 1. DICIONÁRIOS DE TRADUÇÃO OFICIAIS DA IBM (SMF 80 - RACF) ---

MAPA_EVENTOS_IBM = {
    1: "JOB INITIATION / TSO LOGON (RACINIT)",
    2: "RESOURCE ACCESS (RACROUTE REQUEST=AUTH)",
    3: "ADDUSER (Command)",
    4: "ALTUSER (Command)",
    5: "DELUSER (Command)",
    6: "CONNECT (Command)",
    7: "REMOVE (Command)",
    8: "ADDGROUP (Command)",
    9: "ALTGROUP (Command)",
    10: "DELGROUP (Command)",
    11: "ADDSD (Command)",
    12: "ALTDSD (Command)",
    13: "DELSD (Command)",
    14: "RDEFINE (Command)",
    15: "RALTER (Command)",
    16: "RDELETE (Command)",
    17: "REPLACE (Command)",
    18: "GRANT (Command)",
    19: "PERMIT (Command)",
    20: "REVOKE (Command)",
    21: "SEARCH (Command)",
    22: "SETROPTS (Command)",
    23: "RVARY (Command)",
    24: "DATASET ACCESS (SVC 26)",
    25: "GENERIC COMMAND PROCESSING"
}

def decodificar_qualificador_ibm(evt: int, evq: int) -> str:
    """Extrai e traduz de forma explícita a operação (READ, UPDATE, CONTROL, ALTER) com base nos padrões IBM RACF."""
    
    # Contexto de Acesso a Recursos (Eventos 1, 2, 24 e similares)
    if evt in (1, 2, 24):
        # Validação byte a byte mascarando os bits clássicos de intenção de acesso do RACF
        if evq & 0x01 or evq == 1:
            return "READ (Leitura / Execução)"
        elif evq & 0x02 or evq == 2:
            return "UPDATE (Atualização / Modificação Escrita)"
        elif evq & 0x04:
            return "CONTROL (Controle de Permissões VSAM/Estrutural)"
        elif evq & 0x08 or evq == 4:
            return "ALTER (Modificação Total / Exclusão / Criação)"
        elif evq == 0:
            return "READ (Acesso Padrão Concedido)"
            
        return f"ACESSO TENTATIVO (Código {evq})"

    # Contexto de Comandos Administrativos do RACF (Eventos 3 a 23, 25)
    if (3 <= evt <= 23) or evt == 25:
        nome_cmd = MAPA_EVENTOS_IBM.get(evt, "COMANDO").split(" ")[0]
        if evq == 0:
            return f"EXECUÇÃO: {nome_cmd}"
        return f"TENTATIVA REJEITADA: {nome_cmd}"
        
    return f"QUALIFICADOR OPERACIONAL ({evq})"

# --- 2. FUNÇÕES DE DECODIFICAÇÃO MAINFRAME ---

def decodificar_ebcdic(b: bytes) -> str:
    if not b:
        return ""
    try:
        texto = b.decode("cp500").strip()
        if any(c.isprintable() for c in texto):
            return texto
        return b.hex().upper()
    except Exception:
        return b.hex().upper()

def decodificar_packed_decimal(b: bytes) -> str:
    if not b or len(b) < 4:
        return ""
    try:
        hex_str = b.hex()
        corpo = hex_str[1:-1]
        if len(corpo) >= 5:
            seculo = hex_str
            ano = corpo[1:3]
            dia = corpo[3:6]
            prefixo_ano = "20" if seculo in ("1", "2") else "19"
            return f"{prefixo_ano}{ano}-{dia}"
        return hex_str
    except Exception:
        return b.hex().upper()

def mapear_layout_smf80_puro(registro: bytes) -> dict:
    smf80len = struct.unpack(">H", registro[0:2])[0] if len(registro) >= 2 else 0
    smf80seg = struct.unpack(">H", registro[2:4])[0] if len(registro) >= 4 else 0
    smf80flg_raw = registro[4] if len(registro) >= 5 else 0
    smf80rty = registro[5] if len(registro) >= 6 else 0
    
    smf80tme = struct.unpack(">I", registro[6:10])[0] if len(registro) >= 10 else 0
    segundos_totais = smf80tme // 100
    tempo_formatado = f"{segundos_totais // 3600:02d}:{(segundos_totais % 3600) // 60:02d}:{segundos_totais % 60:02d}"

    evt_code = registro[22] if len(registro) >= 23 else 0
    evq_code = registro[23] if len(registro) >= 24 else 0
    err_byte = registro[44] if len(registro) >= 45 else 0
    err_hex = f"0x{err_byte:02X}"

    nome_evento = MAPA_EVENTOS_IBM.get(evt_code, f"Evento Desconhecido ({evt_code})")
    operacao_detalhe = decodificar_qualificador_ibm(evt_code, evq_code)
    
    status_final = "✅" if evq_code == 0 else "❌"

    dados = {
        "SMF80LEN": smf80len,
        "SMF80SEG": smf80seg,
        "SMF80FLG": f"0x{smf80flg_raw:02X}",
        "SMF80RTY": smf80rty,
        "HORA_EVENTO": tempo_formatado,
        "DATA_EVENTO": decodificar_packed_decimal(registro[10:14]),
        "SMF80SID": decodificar_ebcdic(registro[14:18]),
        "SMF80PID": decodificar_ebcdic(registro[18:22]),
        
        "AÇÃO_AUDITADA": nome_evento,
        "DETALHE_DA_OPERAÇÃO": operacao_detalhe,
        "STATUS_SEGURANÇA": status_final,
        
        "SMF80USR": decodificar_ebcdic(registro[24:32]),
        "SMF80GRP": decodificar_ebcdic(registro[32:40]),
        "SMF80REL": struct.unpack(">H", registro[40:42])[0] if len(registro) >= 42 else 0, 
        "SMF80CNT": struct.unpack(">H", registro[42:44])[0] if len(registro) >= 44 else 0, 
        "SMF80ATH": f"0x{registro[44]:02X}" if len(registro) >= 45 else "0x00",
        "SMF80REA": f"0x{registro[45]:02X}" if len(registro) >= 46 else "0x00",
        "SMF80TLV": registro[46] if len(registro) >= 47 else 0,
        "SMF80ERR": err_hex,
        "SMF80TRM": decodificar_ebcdic(registro[47:55]),
        "SMF80JBN": decodificar_ebcdic(registro[55:63]),
        "SMF80RST": struct.unpack(">I", registro[63:67])[0] if len(registro) >= 67 else 0, 
        "SMF80RSD": decodificar_packed_decimal(registro[67:71]),
        "SMF80UID": decodificar_ebcdic(registro[71:79]),
    }
    return dados

# --- 3. GERADOR DE MASSA DE TESTES ---

def texto_para_ebcdic(texto: str, tamanho: int) -> bytes:
    return texto.ljust(tamanho).encode("cp500")[:tamanho]

def criar_packed_decimal_data(ano: int, dias: int) -> bytes:
    ano_str = f"{ano:02d}"
    dias_str = f"{dias:03d}"
    hex_data = f"1{ano_str}{dias_str}f"  
    if len(hex_data) == 7:
        hex_data = "0" + hex_data
    return bytes.fromhex(hex_data)

def gerar_registro_smf80(time_segundos, ano, dia, sid, user, group, jobname, evt, evq, err_byte) -> bytes:
    buffer = bytearray(128)
    struct.pack_into(">H", buffer, 0, 128)  
    struct.pack_into(">H", buffer, 2, 0)    
    buffer[4] = 0x12  
    buffer[5] = 80    
    struct.pack_into(">I", buffer, 6, time_segundos * 100)  
    buffer[10:14] = criar_packed_decimal_data(ano, dia)    
    buffer[14:18] = texto_para_ebcdic(sid, 4)               
    buffer[18:22] = texto_para_ebcdic("RACF", 4)              
    buffer[22] = evt  
    buffer[23] = evq  
    buffer[24:32] = texto_para_ebcdic(user, 8)
    buffer[32:40] = texto_para_ebcdic(group, 8)
    struct.pack_into(">H", buffer, 40, 7730)  
    struct.pack_into(">H", buffer, 42, 1)     
    buffer[44] = err_byte                   
    buffer[47:55] = texto_para_ebcdic("TERMA01", 8)  
    buffer[55:63] = texto_para_ebcdic(jobname, 8)   
    struct.pack_into(">I", buffer, 63, time_segundos * 100)  
    buffer[67:71] = criar_packed_decimal_data(ano, dia)     
    buffer[71:79] = texto_para_ebcdic(user, 8)              
    return bytes(buffer)

def obter_arquivo_teste_5_registros() -> bytes:
    registros = [
        gerar_registro_smf80(37800, 26, 149, "PRD1", "SECADMIN", "SYS1", "READJOB", evt=2, evq=1, err_byte=0x00), # Evq=1 -> READ
        gerar_registro_smf80(40530, 26, 149, "PRD1", "OPERATOR", "STCGRP", "HACKJOB", evt=2, evq=2, err_byte=0x08), # Evq=2 -> UPDATE
        gerar_registro_smf80(43200, 26, 150, "TEST", "DBAUSER", "DBA", "PERMITJB", evt=2, evq=4, err_byte=0x00), # Evq=4 -> ALTER
        gerar_registro_smf80(53115, 25, 365, "PRD2", "ANALYST", "AUDIT", "TSOUSER", evt=19, evq=0, err_byte=0x14),
        gerar_registro_smf80(58800, 26, 1, "PRD1", "BADGUY", "SECURITY", "LOGONFL", evt=1, evq=0, err_byte=0x08)
    ]
    return b"".join(registros)

# --- 4. INTERFACE WEB (STREAMLIT) ---

st.set_page_config(page_title="SMF 80 RACF Expert Auditor", layout="wide")
st.title("📊 Auditor Avançado RACF - Registro SMF Tipo 80")
st.write("Varredura robusta de alta performance alinhada com as especificações oficiais da IBM z/OS.")

with st.sidebar:
    st.subheader("🛠️ Massa de Dados para Testes")
    dados_mockados = obter_arquivo_teste_5_registros()
    st.download_button(
        label="📥 Baixar Amostra Binária RACF",
        data=dados_mockados,
        file_name="dados_auditoria_smf80.bin",
        mime="application/octet-stream"
    )

arquivo_carregado = st.file_uploader(
    "Selecione o arquivo de log EBCDIC (.bin, .dat, .smf)", type=None
)

if arquivo_carregado is not None:
    registro_mapeado = []
    conteudo_bytes = arquivo_carregado.read()
    total_bytes = len(conteudo_bytes)
    
    indices_assinaturas = [idx for idx in range(total_bytes) if conteudo_bytes[idx] == 80]
    
    for idx in indices_assinaturas:
        if idx - 5 >= 0:
            fim_fatia = min(idx + 123, total_bytes)
            fatia_util = conteudo_bytes[idx - 5 : fim_fatia]
            try:
                dados_colunas = mapear_layout_smf80_puro(fatia_util)
                registro_mapeado.append(dados_colunas)
            except Exception:
                pass
    
    # --- APRESENTAÇÃO DOS RESULTADOS ---
    if registro_mapeado:
        df_completo = pd.DataFrame(registro_mapeado)
        st.success(f"🎉 Concluído! Mapeados {len(df_completo)} registros com sucesso na tabela abaixo.")
        st.dataframe(df_completo, use_container_width=True)
        
        with st.expander("🔍 Ver Descarregamento em Ficha Posicional Completa (JSON)"):
            st.json(df_completo.to_dict(orient="records"))
    if not registro_mapeado:
        st.error("Nenhum registro Tipo 80 pôde ser estruturado. Certifique-se de que o arquivo carregado possui dados válidos.")
