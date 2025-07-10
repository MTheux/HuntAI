import streamlit as st
import os
import sys
from dotenv import load_dotenv
import google.generativeai as genai
from PIL import Image
from io import BytesIO
import requests
import time
import json
from urllib.parse import urlparse
import streamlit.components.v1 as components
import yaml
import subprocess
import uuid
import re
import pandas as pd
import logging
import shlex
import zipfile 
import tempfile 
import database
import pandas as pd
from streamlit_option_menu import option_menu

# --- INÍCIO DA CORREÇÃO: INICIALIZAÇÃO DO BANCO DE DADOS ---
# Chame a função de inicialização aqui, no escopo global do script.
# Isso garante que as tabelas serão criadas ANTES de qualquer outra função ser chamada.
try:
    database.init_db()
    # Adicionamos uma flag no session_state para sabermos que o DB está pronto.
    st.session_state.db_initialized = True 
except Exception as e:
    st.error(f"FALHA CRÍTICA AO INICIALIZAR O BANCO DE DADOS: {e}")
    st.warning("O aplicativo pode não funcionar corretamente. Verifique as permissões da pasta.")
    st.session_state.db_initialized = False
# --- FIM DA CORREÇÃO ---

# --- Configurações do LLM (Temperatura Reduzida para Consistência) ---
LLM_TEMPERATURE = 0.1

st.set_page_config(
    layout="wide",
    page_title="HuntIA - Pentest Suite",  # NOVO: Altera o título da aba do navegador
    page_icon="🕵️"  # NOVO: Altera o ícone da aba do navegador. Pode ser um emoji ou o caminho para um arquivo de imagem (ex: "images/favicon.png")
)


# --- Configuração do Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename='huntia.log')
# logging.getLogger().addHandler(logging.StreamHandler()) # Para ver no console durante o desenvolvimento
# --- Fim Configuração do Logging ---

# --- Configuração do LLM e APIs ---
load_dotenv()
API_KEY = os.getenv("GOOGLE_API_KEY")

if not API_KEY:
    st.error("ERRO: A variável de ambiente 'GOOGLE_API_KEY' não está configurada.")
    st.info("Por favor, crie um arquivo .env na raiz do seu projeto e adicione 'GOOGLE_API_KEY=SUA_CHAVE_AQUI'.")
    st.info("Você pode obter sua chave em [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)")
    logging.error("GOOGLE_API_KEY não configurada. O aplicativo não pode continuar.")
    st.stop()

# --- Dicionários de Referência da OWASP ---
OWASP_TOP_10_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)"
}

OWASP_API_TOP_10_2023 = {
    "API1": "Broken Object Level Authorization (BOLA)",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization (BFLA)",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery (SSRF)",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs"
}

# NOVO: OWASP Mobile Top 10 (2024 - versão comum, se houver atualização, ajuste)
OWASP_MOBILE_TOP_10_2024 = {
    "M1": "Improper Credential Usage",
    "M2": "Insecure Communication",
    "M3": "Insecure Authorization",
    "M4": "Insecure Provisioning",
    "M5": "Insufficient Cryptography",
    "M6": "Insecure Data Storage",
    "M7": "Insecure Authentication",
    "M8": "Insufficient Code Integrity",
    "M9": "Improper Session Handling",
    "M10": "Lack of Binary Protections"
}


OWASP_SUBCATEGORIES = {
    "A01": [
        "Insecure Direct Object References (IDOR)", "Missing Function Level Access Control",
        "Privilege Escalation (Vertical/Horizontal)", "Path Traversal",
        "URL Tampering", "Parameter Tampering"
    ],
    "A02": [
        "Weak Hashing Algorithms", "Use of Outdated/Weak Encryption Protocols (e.g., TLS 1.0/1.1)",
        "Hardcoded Cryptographic Keys", "Improper Key Management",
        "Exposure of Sensitive Data in Transit/At Rest"
    ],
    "A03": [
        "SQL Injection (SQLi)", "Cross-Site Scripting (XSS)",
        "Command Injection", "LDAP Injection", "XPath Injection",
        "NoSQL Injection", "Server-Side Template Injection (SSTI)",
        "Code Injection (e.g., PHP, Python, Java)", "Header Injection (e.g., Host Header Injection)"
    ],
    "A04": [
        "Business Logic Flaws", "Lack of Security Design Principles",
        "Trust Boundary Violations", "Feature Overload",
        "Insecure Direct Object References (IDOR) - (also A01, design aspect)"
    ],
    "A05": [
        "Default Passwords/Configurations", "Unnecessary Features/Services Enabled",
        "Improper File/Directory Permissions", "Missing Security Headers",
        "Error Messages Revealing Sensitive Information", "Open Cloud Storage Buckets"
    ],
    "A06": [
        "Using Libraries/Frameworks with Known Vulnerabilities", "Outdated Server Software (e.g., Apache, Nginx, IIS)",
        "Client-Side Libraries with Vulnerabilities", "Lack of Patch Management"
    ],
    "A07": [
        "Weak Password Policies", "Missing Multi-Factor Authentication (MFA)",
        "Session Management Flaws (e.g., fixed session IDs)", "Improper Credential Recovery Mechanisms",
        "Brute-Force Attacks (lack of rate limiting)"
    ],
    "A08": [
        "Insecure Deserialization", "Lack of Integrity Checks on Updates/Packages",
        "Weak Digital Signatures", "Client-Side Trust (e.g., relying on client-side validation)"
    ],
    "A09": [
        "Insufficient Logging of Security Events", "Lack of Alerting on Suspicious Activities",
        "Inadequate Retention of Logs", "Logs Not Protected from Tampering"
    ],
    "A10": "Server-Side Request Forgery (SSRF)"
}


# --- Funções Auxiliares Comuns ---

def get_verbosity_prompt():
    """Retorna a instrução de prompt baseada na verbosidade selecionada."""
    verbosity = st.session_state.get('llm_verbosity', "Detalhado (Técnico)")
    
    if verbosity == "Conciso (Resumo Executivo)":
        return "Instrução de Verbosidade: Seja extremamente conciso e foque no impacto para o negócio. Evite jargões técnicos profundos. A resposta deve ser adequada para um executivo (C-Level)."
    elif verbosity == "Super Detalhado (Educacional)":
        return "Instrução de Verbosidade: Seja extremamente detalhado em suas explicações. Defina cada conceito técnico como se estivesse ensinando um iniciante. Forneça múltiplos exemplos e um contexto aprofundado."
    else: # Padrão: "Detalhado (Técnico)"
        return "Instrução de Verbosidade: Forneça uma resposta técnica completa e precisa, adequada para uma equipe de desenvolvimento ou segurança. Use jargões técnicos apropriadamente."


def get_log_file_content(log_file_path='huntia.log'):
    """Lê o conteúdo do arquivo de log."""
    if os.path.exists(log_file_path):
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    return "Log file not found."


def is_valid_url(url_string):
    """Verifica se a string é uma URL bem formada."""
    if not url_string:
        return False
    try:
        result = urlparse(url_string)
        # Verifica se há esquema (http, https) e network location (domínio)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def get_gemini_models_cached():
    if 'llm_models' not in st.session_state:
        st.session_state.llm_models = {'vision_model': None, 'text_model': None, 'initialized': False}

    if not st.session_state.llm_models['initialized']:
        genai.configure(api_key=API_KEY)

        llm_model_vision_temp = None
        llm_model_text_temp = None

        vision_model_priority = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro-vision"]
        text_model_priority = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro"]

        try:
            available_models = list(genai.list_models())

            for preferred_name in vision_model_priority:
                for m in available_models:
                    if preferred_name in m.name and 'generateContent' in m.supported_generation_methods:
                        llm_model_vision_temp = genai.GenerativeModel(m.name)
                        break
                if llm_model_vision_temp:
                    break

            for preferred_name in text_model_priority:
                for m in available_models:
                    if preferred_name in m.name and 'generateContent' in m.supported_generation_methods:
                        llm_model_text_temp = genai.GenerativeModel(m.name, generation_config={"temperature": LLM_TEMPERATURE})
                        break
                if llm_model_text_temp:
                    break

            if not llm_model_vision_temp:
                st.error("ERRO: Nenhum modelo LLM de visão adequado (gemini-1.5-flash/pro ou gemini-pro-vision) encontrado.")
                st.info("Por favor, configure sua GOOGLE_API_KEY e verifique a disponibilidade de modelos no Google AI Studio.")
                logging.error("Nenhum modelo LLM de visão adequado encontrado.")
            if not llm_model_text_temp:
                st.error("ERRO: Nenhum modelo LLM de texto adequado (gemini-1.5-flash/pro ou gemini-pro) encontrado.")
                st.info("Por favor, configure sua GOOGLE_API_KEY e verifique a disponibilidade de modelos no Google AI Studio.")
                logging.error("Nenhum modelo LLM de texto adequado encontrado.")

        except Exception as e:
            st.error(f"ERRO ao listar ou selecionar modelos do Gemini: {e}")
            st.info("Verifique sua conexão com a internet e sua GOOGLE_API_KEY.")
            logging.exception("Erro ao listar ou selecionar modelos do Gemini.")

        st.session_state.llm_models['vision_model'] = llm_model_vision_temp
        st.session_state.llm_models['text_model'] = llm_model_text_temp
        st.session_state.llm_models['initialized'] = True
    
    return st.session_state.llm_models['vision_model'], st.session_state.llm_models['text_model']


def obter_resposta_llm(model_instance, prompt_parts):
    if model_instance is None:
        st.error("Erro: O modelo LLM não foi inicializado corretamente. Não é possível gerar conteúdo.")
        logging.error("Tentativa de gerar conteúdo com modelo LLM não inicializado.")
        return None
    try:
        response = model_instance.generate_content(prompt_parts)
        logging.info(f"Resposta do LLM obtida com sucesso do modelo {model_instance.model_name}.")
        return response.text
    except Exception as e:
        st.error(f"Erro ao comunicar com o LLM: {e}")
        st.info("Verifique se a sua conexão com a internet está ativa e se o modelo LLM está funcionando.")
        logging.exception(f"Erro ao comunicar com o LLM {model_instance.model_name}.")
        return None

def formatar_resposta_llm(resposta_bruta):
    return resposta_bruta

@st.cache_data(show_spinner=False)

def mapear_falha_para_owasp(_llm_text_model, falha_input):
    owasp_list = "\n".join([f"{code}: {name}" for code, name in OWASP_TOP_10_2021.items()])

    prompt = (
        f"Qual categoria da OWASP Top 10 (2021) melhor representa a vulnerabilidade ou técnica de ataque '{falha_input}'?"
        f"\n\nConsidere a seguinte lista de categorias OWASP Top 10 (2021):"
        f"\n{owasp_list}"
        f"\n\nSe a entrada for um nome de falha específica (como 'XSS', 'SQL Injection', 'IDOR'), identifique a categoria correta e retorne apenas o CÓDIGO (ex: A03)."
        f"Se a entrada for já um código OWASP (ex: 'A01'), retorne-o diretamente."
        f"Se não tiver certeza ou se não se encaixar em nenhuma categoria clara, responda 'INDEFINIDO'."
        f"\nExemplos: 'SQL Injection' -> 'A03', 'Cross-Site Scripting' -> 'A03', 'IDOR' -> 'A01', 'Broken Access Control' -> 'A01', 'Clickjacking' -> 'A04', 'A03' -> 'A03'."
        f"\nResposta esperada é APENAS o código OWASP."
    )

    with st.spinner(f"Tentando mapear '{falha_input}' para uma categoria OWASP..."):
        logging.info(f"Tentando mapear '{falha_input}' para categoria OWASP.")
        resposta = obter_resposta_llm(_llm_text_model, [prompt])

    if resposta:
        codigo_owasp = resposta.strip().upper().split(':')[0].split(' ')[0]
        if codigo_owasp in OWASP_TOP_10_2021:
            logging.info(f"Mapeado '{falha_input}' para OWASP {codigo_owasp}.")
            return codigo_owasp
        elif codigo_owasp == "INDEFINIDO":
            st.warning("O LLM não conseguiu mapear a falha para uma categoria OWASP específica.")
            logging.warning(f"LLM não mapeou '{falha_input}' para categoria OWASP (INDEFINIDO).")
            return None
        else:
            st.warning(f"O LLM retornou um código inesperado: '{codigo_owasp}'.")
            logging.warning(f"LLM retornou código inesperado '{codigo_owasp}' para '{falha_input}'.")
            return None
    logging.warning(f"Nenhuma resposta do LLM para mapeamento OWASP de '{falha_input}'.")
    return None

def parse_vulnerability_summary(text_response):
    summary = {
        "Total": 0, "Críticas": 0, "Altas": 0, "Médias": 0, "Baixas": 0
    }

    lines = text_response.split('\n')
    summary_line_found = False
    parsed_content = []

    for i, line in enumerate(lines):
        # Esta é a linha que procura pela linha de resumo.
        # Adicione "Total de Achados Mobile:" para garantir que o parser encontre a linha no caso mobile.
        if ("Total de Vulnerabilidades:" in line or "Total de Ameaças:" in line or \
            "Total de Vulnerabilidades API:" in line or "Total de Insights:" in line or \
            "Total de Eventos:" in line or "Total de Achados:" in line or \
            "Total de Achados de Validação:" in line or "Total de Achados Mobile:" in line or \
            "Total Achados:" in line) and not summary_line_found: # Adicione "Total Achados:" para o caso específico da imagem
            summary_line = line
            summary_line_found = True
        else:
            parsed_content.append(line)

    if summary_line_found:
        # Usar regexes mais flexíveis para capturar os números após os rótulos
        total_match = re.search(r'Total(?: de Achados| de Vulnerabilidades| de Ameaças| de Insights| de Eventos| de Achados de Validação| Mobile)?:\s*(\d+)', summary_line)
        crit_match = re.search(r'Críticas?:\s*(\d+)', summary_line) # Suporta Críticas: ou Críticos:
        altas_match = re.search(r'Altas?:\s*(\d+)', summary_line) # Suporta Altas: ou Altos:
        medias_match = re.search(r'Médios?:\s*(\d+)', summary_line) # Suporta Médias: ou Médios:
        baixas_match = re.search(r'Baixas?:\s*(\d+)', summary_line) # Suporta Baixas: ou Baixos:

        if total_match:
            summary["Total"] = int(total_match.group(1))
        if crit_match:
            summary["Críticas"] = int(crit_match.group(1))
        if altas_match:
            summary["Altas"] = int(altas_match.group(1))
        if medias_match:
            summary["Médias"] = int(medias_match.group(1))
        if baixas_match:
            summary["Baixas"] = int(baixas_match.group(1))
            
        # Para os campos de validação de pentest (se ainda forem usados, mantenha)
        cobertura_alta_match = re.search(r'Cobertura Alta:\s*(\d+)', summary_line)
        cobertura_media_match = re.search(r'Cobertura Média:\s*(\d+)', summary_line)
        cobertura_baixa_match = re.search(r'Cobertura Baixa:\s*(\d+)', summary_line)
        lacunas_match = re.search(r'Lacunas:\s*(\d+)', summary_line)

        if cobertura_alta_match:
            summary["Cobertura Alta"] = int(cobertura_alta_match.group(1))
        if cobertura_media_match:
            summary["Cobertura Média"] = int(cobertura_media_match.group(1))
        if cobertura_baixa_match:
            summary["Cobertura Baixa"] = int(cobertura_baixa_match.group(1))
        if lacunas_match:
            summary["Lacunas"] = int(lacunas_match.group(1))

    return summary, "\n".join(parsed_content).strip()

def parse_raw_http_request(raw_request):
    method = ""
    path = ""
    full_url = ""
    headers = {}
    body = ""

    lines = raw_request.splitlines()

    # Parse first line (method, path, HTTP version)
    if lines and lines[0].strip():
        first_line_parts = lines[0].split(' ')
        if len(first_line_parts) >= 2:
            method = first_line_parts[0].strip()
            path = first_line_parts[1].strip()

    body_started = False
    for line in lines[1:]:
        if not line.strip() and not body_started: # Empty line indicates end of headers, start of body
            body_started = True
            continue

        if not body_started: # Still parsing headers
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        else: # Parsing body
            body += line + '\n'

    # Try to construct full_url from Host header and path
    if 'Host' in headers and path:
        host = headers['Host']
        # Determine scheme based on common ports or explicitly in request line
        scheme = "https" if "443" in host or raw_request.lower().splitlines()[0].startswith("https") else "http"
        # Handle cases where path might already include domain, or just be a root path
        if path.startswith('http://') or path.startswith('https://'):
            full_url = path # Path is already a full URL
        elif path.startswith('/'):
            full_url = f"{scheme}://{host}{path}"
        else: # Relative path without leading slash, assume it follows host directly
            full_url = f"{scheme}://{host}/{path}" # Add a slash for safety

    return {
        "method": method,
        "path": path,
        "full_url": full_url,
        "headers": headers,
        "body": body.strip()
    }


# --- Funções das "Páginas" --- (Definição de todas as funções antes de main())

def home_page():
    st.header("Bem-vindo ao HuntIA - Plataforma de Segurança 🛡️")
    st.markdown("---")
    
    # Mensagem de status para guiar o usuário sobre como começar
    st.info("""
        **Comece pela página de 'Configurações' na barra lateral para:**
        - Criar ou selecionar um projeto para salvar seu trabalho.
        - Ativar o 'Modo Rascunho' para análises rápidas e não salvas.
        - Definir o contexto global do pentest (Perfil do Atacante e Cenário).
    """)

    st.markdown("""
        ### Sua suíte de reconhecimento e pentest inteligente, com o poder do LLM!
        
        Após configurar sua sessão, selecione uma das ferramentas na barra lateral para iniciar sua análise.
    """)
    logging.info("Página inicial acessada.")

def get_global_context_prompt():
    """Retorna a string de contexto global a ser injetada nos prompts do LLM."""
    profile = st.session_state.get('global_profile', "Nenhum")
    scenario = st.session_state.get('global_scenario', "Nenhum")
    
    context_parts = []
    if profile != "Nenhum":
        context_parts.append(f"com um perfil de atacante '{profile}'")
    if scenario != "Nenhum":
        context_parts.append(f"em um cenário de ataque de '{scenario}'")
    
    if context_parts:
        # Instrução mais detalhada para o LLM usar o contexto
        return f"Considere-se atuando como um pentester {', e '.join(context_parts)}. Ajuste suas respostas com base nesse conhecimento, fornecendo retornos como se fosse um especialista nesse contexto, priorizando a profundidade e o tipo de vulnerabilidades, métodos de exploração e mitigações que seriam relevantes para esse contexto específico."
    return "Considere-se um pentester genérico e experiente, fornecendo respostas abrangentes." # Contexto padrão se nada for selecionado

# CÓDIGO ATUALIZADO para correlation_dashboard_page
def settings_page():
    st.header("Configurações Globais e Gerenciamento de Projetos ⚙️")
    st.markdown("---")

    # --- Seção de Controle de Comportamento do LLM ---
    st.subheader("Controle de Comportamento do LLM")

    # Inicializa o estado da verbosidade se não existir
    if 'llm_verbosity' not in st.session_state:
        st.session_state.llm_verbosity = "Detalhado (Técnico)" # Valor padrão

    st.session_state.llm_verbosity = st.selectbox(
        "Modo de Verbosidade do Relatório:",
        options=["Conciso (Resumo Executivo)", "Detalhado (Técnico)", "Super Detalhado (Educacional)"],
        index=["Conciso (Resumo Executivo)", "Detalhado (Técnico)", "Super Detalhado (Educacional)"].index(st.session_state.llm_verbosity),
        help="Define o nível de detalhe das respostas do LLM em toda a aplicação."
    )
    st.markdown("---")
    
    # --- Seção de Modo de Operação ---
    st.subheader("Modo de Operação")
    
    if 'modo_rascunho' not in st.session_state: 
        st.session_state.modo_rascunho = True

    st.session_state.modo_rascunho = st.checkbox(
        "Ativar Modo Rascunho (Não Salvar Análises)", 
        value=st.session_state.modo_rascunho,
        help="Quando ativado, você pode usar as ferramentas sem selecionar um projeto, e os resultados não serão salvos no banco de dados."
    )

    if st.session_state.modo_rascunho:
        st.info("Modo Rascunho Ativo ✏️: Os resultados das análises não serão salvos.")
    else:
        st.success("Modo de Projeto Ativo 💾: Os resultados das análises serão salvos no projeto selecionado.")
    
    st.markdown("---")

    # --- Seção do Gerenciador de Projetos ---
    st.subheader("Gerenciador de Projetos")

    is_disabled = st.session_state.modo_rascunho

    if is_disabled:
        st.warning("O gerenciamento de projetos está desabilitado pois o Modo Rascunho está ativo.")

    lista_de_projetos = database.listar_projetos()
    opcoes_projetos = {nome: id for id, nome in lista_de_projetos}
    nomes_projetos_para_selectbox = ["Nenhum"] + list(opcoes_projetos.keys())

    try:
        index_selecionado = nomes_projetos_para_selectbox.index(st.session_state.projeto_ativo_nome) if st.session_state.projeto_ativo_nome else 0
    except ValueError:
        index_selecionado = 0

    col1, col2 = st.columns(2)
    with col1:
        projeto_selecionado_nome = st.selectbox(
            "Selecione um Projeto Ativo:",
            options=nomes_projetos_para_selectbox,
            index=index_selecionado,
            key="project_selector_settings_page",
            disabled=is_disabled
        )

        if not is_disabled:
            if projeto_selecionado_nome and projeto_selecionado_nome != "Nenhum":
                if st.session_state.projeto_ativo_nome != projeto_selecionado_nome:
                    st.session_state.projeto_ativo_id = opcoes_projetos[projeto_selecionado_nome]
                    st.session_state.projeto_ativo_nome = projeto_selecionado_nome
                    logging.info(f"Projeto '{projeto_selecionado_nome}' selecionado.")
                    st.rerun()
            elif st.session_state.projeto_ativo_nome and projeto_selecionado_nome == "Nenhum":
                st.session_state.projeto_ativo_id = None
                st.session_state.projeto_ativo_nome = None
                st.rerun()
    
    with col2:
        novo_projeto_nome = st.text_input("Ou crie um novo projeto:", key="new_project_input_settings_page", disabled=is_disabled)
        if st.button("Criar Projeto", key="create_project_button_settings_page", disabled=is_disabled):
            if novo_projeto_nome:
                sucesso, novo_projeto_id, mensagem = database.criar_projeto(novo_projeto_nome)
                if sucesso:
                    st.toast(mensagem, icon="🎉")
                    st.session_state.projeto_ativo_nome = novo_projeto_nome
                    st.session_state.projeto_ativo_id = novo_projeto_id
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(mensagem)
            else:
                st.warning("Digite um nome para o novo projeto.")
    
    st.markdown("---")

    # --- Seção de Contexto Global ---
    st.subheader("Contexto da Análise (Engenharia de Prompt)")
    col_profile, col_scenario = st.columns(2)

    with col_profile:
        st.session_state.global_profile = st.selectbox(
            "Perfil do Atacante:",
            options=["Nenhum", "Novato", "Experiente", "APT (Advanced Persistent Threat)"],
            index=["Nenhum", "Novato", "Experiente", "APT (Advanced Persistent Threat)"].index(st.session_state.get('global_profile', 'Nenhum')),
            key="global_profile_select_settings"
        )
    with col_scenario:
        st.session_state.global_scenario = st.selectbox(
            "Cenário de Ataque:",
            options=["Nenhum", "Acesso Interno", "Acesso Externo (Internet)", "Phishing", "Red Team Exercise"],
            index=["Nenhum", "Acesso Interno", "Acesso Externo (Internet)", "Phishing", "Red Team Exercise"].index(st.session_state.get('global_scenario', 'Nenhum')),
            key="global_scenario_select_settings"
        )

def correlation_dashboard_page(llm_model_text):
    st.header("Correlation Dashboard: Conectando os Pontos 🧠")
    st.markdown("""
        Esta página atua como o cérebro central do seu projeto. Ela agrega os resultados de todas as outras
        ferramentas e usa o LLM para identificar correlações de risco e vetores de ataque combinados
        que poderiam passar despercebidos em análises isoladas.
    """)
    logging.info("Página Correlation Dashboard acessada.")

    if 'correlation_result' not in st.session_state:
        st.session_state.correlation_result = ""

    if not st.session_state.get('projeto_ativo_id'):
        st.error("Por favor, selecione ou crie um projeto na barra lateral para usar este módulo.")
        st.stop()
    
    st.info(f"Analisando correlações para o projeto: **{st.session_state.projeto_ativo_nome}**")

    # 1. Agregação de Dados do Projeto Ativo
    st.subheader("1. Resumo dos Dados Coletados para o Projeto")
    
    # Carregar todas as análises salvas do banco de dados para o projeto atual
    analises_salvas = database.carregar_analises_do_projeto(st.session_state.projeto_ativo_id)
    
    dados_agregados_para_prompt = []
    dados_para_exibir = []

    if not analises_salvas:
        st.warning("Nenhuma análise foi salva neste projeto ainda. Por favor, use as outras ferramentas primeiro para gerar dados.")
        st.stop()

    # --- INÍCIO DA MODIFICAÇÃO (Processar os novos tipos de análise) ---
    for tipo_analise, resumo_input, resultado_completo in analises_salvas:
        # Adiciona um resumo para exibição no dashboard
        dados_para_exibir.append(f"**Fonte:** `{tipo_analise}`\n**Input:** {resumo_input}\n")
        
        # Adiciona um resumo mais detalhado para o prompt do LLM
        # Para análises de texto, o resumo do input é suficiente
        if tipo_analise in ["OWASP Vulnerability Details", "Static Code Analyzer", "OpenAPI Analyzer"]:
             dados_agregados_para_prompt.append(f"**Achado de '{tipo_analise}':**\n{resumo_input}\n")
        # Para o Deep HTTP Insight, podemos extrair a tabela de riscos para o prompt
        elif tipo_analise == "Deep HTTP Insight":
            tabela_riscos_match = re.search(r"## Tabela de Riscos\n(.*?)(?=\n##|\Z)", resultado_completo, re.DOTALL | re.IGNORECASE)
            if tabela_riscos_match:
                tabela_formatada = tabela_riscos_match.group(1).strip()
                dados_agregados_para_prompt.append(f"**Achado de '{tipo_analise}':**\n{resumo_input}\n**Tabela de Riscos Identificados:**\n{tabela_formatada}\n")
            else:
                dados_agregados_para_prompt.append(f"**Achado de '{tipo_analise}':**\n{resumo_input}\n")
        else:
            # Fallback para outros tipos de análise
            dados_agregados_para_prompt.append(f"**Achado de '{tipo_analise}':**\n{resumo_input}\n")
    # --- FIM DA MODIFICAÇÃO ---

    with st.expander("Clique para ver os dados agregados que serão enviados para análise"):
        for dado in dados_para_exibir:
            st.markdown(dado)
            st.markdown("---")

    st.subheader("2. Análise de Correlação de Risco")
    if st.button("Analisar Correlações", key="analyze_correlations_button"):
        with st.spinner("O HuntIA está pensando e conectando os pontos..."):
            logging.info(f"Correlation Dashboard: Iniciando análise de correlação para o projeto ID {st.session_state.projeto_ativo_id}.")
            
            global_context_prompt = get_global_context_prompt()
            
            correlation_prompt = (
                "Você é um analista de segurança sênior e um 'Threat Hunter', especializado em conectar pontos e identificar vetores de ataque complexos."
                f"{global_context_prompt}\n\n"
                "A seguir estão os resumos de várias análises de segurança realizadas em um mesmo projeto. "
                "Sua missão é atuar como um 'meta-analisador'. Analise TODOS os achados em conjunto. "
                "Sua tarefa NÃO é repetir os achados, mas sim encontrar **correlações, dependências e vetores de ataque combinados** que um analista olhando para cada ferramenta isoladamente poderia perder.\n\n"
                "**Dados Agregados para Análise:**\n"
                "```\n"
                f"{'\n\n'.join(dados_agregados_para_prompt)}"
                "\n```\n\n"
                "**Formato da Resposta:**\n"
                "Forneça sua análise em uma lista de vetores de ataque correlacionados. Para cada um, use o seguinte formato Markdown:\n\n"
                "### Vetor de Ataque Correlacionado #[Número]\n"
                "**Descrição do Vetor:** (Descreva o cenário de ataque combinado de forma clara e concisa).\n"
                "**Pontos de Conexão:** (Explique exatamente quais achados de diferentes ferramentas se conectam. Ex: 'A resposta HTTP do *Deep HTTP Insight* mostrou um cabeçalho 'Server: Apache/2.4.29'. A consulta no *OWASP Vulnerability Details* sobre 'vulnerabilidades Apache 2.4.29' pode revelar exploits conhecidos para esta versão.').\n"
                "**Próximo Passo Tático Sugerido:** (Sugira a próxima ação prática que um pentester deveria tomar. Ex: 'Use o Tactical Command Orchestrator para gerar um comando `nmap -sV --script http-vuln-cve*` contra o alvo para confirmar as vulnerabilidades conhecidas.').\n"
                "**Nível de Risco da Correlação:** [Crítico/Alto/Médio]\n"
                "---"
            )

            correlation_raw = obter_resposta_llm(llm_model_text, [correlation_prompt])
            
            if correlation_raw:
                st.session_state.correlation_result = correlation_raw
                logging.info(f"Correlation Dashboard: Análise de correlação concluída com sucesso para o projeto ID {st.session_state.projeto_ativo_id}.")
                # Salva a própria análise de correlação no banco de dados
                try:
                    database.salvar_analise(
                        projeto_id=st.session_state.projeto_ativo_id,
                        tipo_analise="Correlation Analysis",
                        resumo_input=f"Correlação baseada em {len(dados_para_exibir)} achados do projeto.",
                        resultado_completo=correlation_raw
                    )
                    st.toast("Análise de correlação salva no projeto!", icon="🧠")
                except Exception as e:
                    st.error(f"Houve um erro ao salvar a análise de correlação no banco de dados: {e}")
            else:
                st.session_state.correlation_result = "Não foi possível obter uma análise de correlação. Tente novamente."
                logging.error(f"Correlation Dashboard: Falha ao obter análise de correlação do LLM para o projeto ID {st.session_state.projeto_ativo_id}.")
                
    if st.session_state.correlation_result:
        st.markdown(st.session_state.correlation_result)
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="correlation_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback Correlation Dashboard: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="correlation_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback Correlation Dashboard: Precisa de Melhoria.")

def owasp_scout_visual_page(llm_model_vision, llm_model_text):
    st.header("OWASP Image Analyzer: Análise de Vulnerabilidades em Imagens 👁️")
    st.markdown("""
        Envie um print, um trecho de código em imagem, ou qualquer diagrama e pergunte ao HuntIA se ele detecta vulnerabilidades OWASP Top 10.
        Quanto mais detalhes na sua pergunta, melhor a análise!
    """)
    logging.info("Página OWASP Image Analyzer acessada.")

    # --- Início do Bloco Universal de Verificação ---
    if not st.session_state.get('projeto_ativo_id') and not st.session_state.get('modo_rascunho'):
        st.error("Por favor, selecione um projeto ou ative o 'Modo Rascunho' na página de Configurações.")
        st.stop()
    
    if st.session_state.get('modo_rascunho'):
        st.info("Você está no Modo Rascunho. Esta análise não será salva. ✏️")
    else:
        st.success(f"Analisando imagens para o projeto: **{st.session_state.projeto_ativo_nome}**")
    st.markdown("---")
    # --- Fim do Bloco Universal ---

    # Initialize session state variables for this page
    if 'owasp_image_uploaded_list' not in st.session_state:
        st.session_state.owasp_image_uploaded_list = []
    if 'owasp_question_text' not in st.session_state:
        st.session_state.owasp_question_text = ""
    if 'owasp_analysis_result' not in st.session_state:
        st.session_state.owasp_analysis_result = ""
    if 'owasp_consider_waf_state' not in st.session_state:
        st.session_state.owasp_consider_waf_state = False

    def reset_owasp_scout_visual():
        st.session_state.owasp_image_uploaded_list = []
        st.session_state.owasp_question_text = ""
        st.session_state.owasp_analysis_result = ""
        st.session_state.owasp_consider_waf_state = False
        logging.info("OWASP Image Analyzer: Reset de campos.")
        st.rerun()

    if st.button("Limpar e Fazer Nova Consulta", key="reset_visual_analysis_button"):
        reset_owasp_scout_visual()

    uploaded_files = st.file_uploader(
        "Selecione uma ou mais imagens para análise (JPG, JPEG, PNG)",
        type=["jpg", "jpeg", "png"],
        accept_multiple_files=True,
        key="owasp_file_uploader"
    )

    if uploaded_files:
        existing_file_fingerprints = {(e['name'], e['image'].size) for e in st.session_state.owasp_image_uploaded_list if 'name' in e and 'image' in e}
        
        for uploaded_file in uploaded_files:
            try:
                img_bytes = uploaded_file.getvalue()
                img = Image.open(BytesIO(img_bytes))
                
                file_fingerprint = (uploaded_file.name, img.size)
                
                if file_fingerprint not in existing_file_fingerprints:
                    st.session_state.owasp_image_uploaded_list.append({
                        'image': img,
                        'name': uploaded_file.name,
                        'id': str(uuid.uuid4())
                    })
                    existing_file_fingerprints.add(file_fingerprint)
                    logging.info(f"OWASP Image Analyzer: Imagem '{uploaded_file.name}' carregada.")
                else:
                    st.info(f"Arquivo '{uploaded_file.name}' já carregado. Ignorando duplicata.")
            except Exception as e:
                st.error(f"Erro ao carregar a imagem {uploaded_file.name}: {e}")
                logging.error(f"OWASP Image Analyzer: Erro ao carregar imagem '{uploaded_file.name}': {e}")

    if st.session_state.owasp_image_uploaded_list:
        st.markdown("#### Imagens Carregadas:")
        images_to_remove = []
        for i, img_data in enumerate(st.session_state.owasp_image_uploaded_list):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.image(img_data['image'], caption=f"Pré-visualização Imagem {i+1}: {img_data.get('name', 'N/A')}", use_container_width=True)
            with col2:
                if st.button(f"Remover Imagem {i+1}", key=f"remove_owasp_img_btn_{img_data['id']}"):
                    images_to_remove.append(i)
        
        if images_to_remove:
            for index in sorted(images_to_remove, reverse=True):
                logging.info(f"OWASP Image Analyzer: Imagem '{st.session_state.owasp_image_uploaded_list[index].get('name', 'N/A')}' removida.")
                del st.session_state.owasp_image_uploaded_list[index]
            st.rerun()

    question = st.text_area(
        "Sua pergunta sobre a vulnerabilidade ou contexto:",
        value=st.session_state.owasp_question_text,
        placeholder="Ex: 'Esta tela de login é vulnerável?', 'Há XSS neste código?', 'Qual vulnerabilidade está presente neste diagrama?'",
        key="owasp_question_input"
    )
    st.session_state.owasp_question_text = question

    consider_waf = st.checkbox(
        "Considerar bypass de WAF?",
        value=st.session_state.owasp_consider_waf_state,
        key="owasp_waf_checkbox"
    )

    if st.button("Analisar Vulnerabilidade", key="owasp_analyze_button_main"):
        if not st.session_state.owasp_image_uploaded_list:
            st.error("Por favor, selecione pelo menos uma imagem para análise.")
            return
        elif not st.session_state.owasp_question_text:
            st.error("Por favor, digite sua pergunta sobre a vulnerabilidade nas imagens.")
            return
        else:
            with st.spinner("Analisando suas imagens em busca de vulnerabilidades OWASP..."):
                logging.info(f"OWASP Image Analyzer: Iniciando análise para '{st.session_state.owasp_question_text}' com {len(st.session_state.owasp_image_uploaded_list)} imagens.")

                # --- Início das Melhorias de Prompt ---
                global_context_prompt = get_global_context_prompt()
                verbosity_prompt = get_verbosity_prompt()
                instrucao_chain_of_thought = (
                    "\n\n**Instrução de Raciocínio Interno:** Antes de formular sua resposta final, siga estes passos de análise mentalmente: "
                    "1. Examine cada imagem individualmente e identifique os elementos técnicos visíveis (ex: formulários, trechos de código, URLs, nomes de parâmetros, respostas de servidor). "
                    f"2. Com base na pergunta do usuário ('{st.session_state.owasp_question_text}'), liste os vetores de ataque OWASP mais prováveis para os elementos identificados. "
                    "3. Para cada vetor de ataque potencial, formule uma hipótese de como ele se aplicaria ao contexto visual específico. "
                    "4. Apenas após concluir essa análise interna, construa a resposta final para o usuário, seguindo estritamente o formato de saída e o nível de verbosidade solicitados."
                )
                # --- Fim das Melhorias de Prompt ---
                
                # Usando o seu prompt detalhado e injetando as novas instruções
                llm_input_parts = [
                    f"Você é um especialista em segurança da informação e pentest.",
                    f"{global_context_prompt}",
                    f"{verbosity_prompt}",
                    instrucao_chain_of_thought,
                    f"\n\n**Tarefa Principal:** Analise TODAS as imagens fornecidas e o seguinte contexto/pergunta: '{st.session_state.owasp_question_text}'.",
                    f"\n\nIdentifique possíveis vulnerabilidades de segurança da informação relevantes para a OWASP Top 10 (2021) que possam ser inferidas das imagens ou do contexto fornecido.",
                    f"\n\n**Formato de Saída Solicitado:** Para cada vulnerabilidade identificada, forneça os seguintes detalhes de forma concisa e prática, utilizando formato Markdown para títulos e blocos de código:",
                    f"\n\n## 1. Detalhamento da Falha",
                    f"\nUma breve explicação do que é a vulnerabilidade, como ela ocorre e os cenários comuns de impacto, **especificamente como se relaciona às imagens ou ao contexto.** If the vulnerability is visible in a specific image, mention which image (e.g., 'Na Imagem 1, ...').",
                    f"\n\n## 2. Categoria OWASP (2021)",
                    f"\nIndique o CÓDIGO e o NOME da categoria da OWASP Top 10 (2021) à qual esta vulnerabilidade pertence (ex: A03: Injection). Use a lista: {', '.join([f'{c}: {n}' for c, n in OWASP_TOP_10_2021.items()])}. Se for uma subcategoria, mencione-la também.",
                    f"\n\n## 3. Técnicas de Exploração Detalhadas",
                    f"\nDescreva passo a passo os métodos comuns e abordagens para testar e explorar esta vulnerabilidade, focando em como as imagens podem estar relacionadas. Seja didático e prático.\n",
                    f"\n\n## 4. Ferramentas Sugeridas",
                    f"\nListe as ferramentas de segurança e pentest (ex: Burp Suite, Nmap, SQLmap, XSSer, Nessus, Nikto, Metasploit, etc.) que seriam úteis para descobrir e explorar esta vulnerabilidade, explicando brevemente como cada uma se aplicaria.\n",
                    f"\n\n## 5. Severidade",
                    f"\nClassifique a severidade desta vulnerabilidade: [Crítica/Alta/Média/Baixa].\n",
                    f"\n\n## 6. Dicas de Exploração / Próximos Passos Práticos",
                    f"\nCom base na falha identificada e no contexto das imagens, forneça dicas práticas e os próximos passos que um pentester faria para explorar ou confirmar a falha. Inclua instruções sobre como usar as ferramentas sugeridas e payloads de teste, se aplicável. Seja acionável.\n"
                ]

                if st.session_state.owasp_consider_waf_state:
                    llm_input_parts.append(f"\n\n## 7. Dicas de Bypass de WAF")
                    llm_input_parts.append(f"\nForneça estratégias, técnicas e exemplos práticos (se aplicável à vulnerabilidade) para contornar ou evadir a detecção de um Web Application Firewall (WAF) ao tentar explorar esta falha. Inclua exemplos de payloads ou modificações de requisições que podem ajudar a testar o presença ou bypass do WAF.")
                    poc_section_num = 8
                else:
                    poc_section_num = 7

                llm_input_parts.append(f"\n\n## {poc_section_num}. Prova de Conceito (PoC)")
                llm_input_parts.append(f"\nForneça **exemplos práticos de comandos de terminal, requisições HTTP (com `curl` ou similar), ou payloads de código (Python, JS, etc.)** que demonstrem a exploração. Esses exemplos devem ser claros, prontos para uso (com pequenas adaptações) e encapsulados em blocos de código Markdown (` ``` `). Relacione o PoC às imagens ou contexto, se possível.")

                llm_input_parts.append(f"\n\nSeu objetivo é ser direto, útil e focado em ações e informações completas para um pentester. Se as imagens não contiverem vulnerabilidades óbvias, ou a pergunta for muito genérica, indique isso de forma clara.")
                
                for img_data in st.session_state.owasp_image_uploaded_list:
                    llm_input_parts.append(img_data['image'])

                analysis_result = obter_resposta_llm(llm_model_vision, llm_input_parts)

                if analysis_result:
                    st.session_state.owasp_analysis_result = analysis_result
                    logging.info("OWASP Image Analyzer: Análise concluída com sucesso.")

                    # Padrão Universal de Salvamento
                    if not st.session_state.get('modo_rascunho', False):
                        try:
                            nomes_imagens = ", ".join([img['name'] for img in st.session_state.owasp_image_uploaded_list])
                            resumo_para_db = f"Análise de Imagem: '{st.session_state.owasp_question_text}' em [{nomes_imagens}]"
                            database.salvar_analise(
                                projeto_id=st.session_state.projeto_ativo_id,
                                tipo_analise="OWASP Image Analyzer",
                                resumo_input=resumo_para_db,
                                resultado_completo=analysis_result
                            )
                            st.toast("Análise de imagem salva com sucesso no projeto!", icon="💾")
                        except Exception as e:
                            st.error(f"Houve um erro ao salvar a análise no banco de dados: {e}")
                    else:
                        st.toast("Modo Rascunho: Resultado não salvo.", icon="✏️")
                else:
                    st.session_state.owasp_analysis_result = "Não foi possível obter uma resposta do Gemini. Tente novamente."
                    logging.error("OWASP Image Analyzer: Falha na obtenção da resposta do LLM.")

    if st.session_state.owasp_analysis_result:
        st.subheader("Resultados da Análise Visual")
        st.markdown(st.session_state.owasp_analysis_result)
        
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="owasp_visual_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback OWASP Image Analyzer: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="owasp_visual_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback OWASP Image Analyzer: Precisa de Melhoria.")

def owasp_text_analysis_page(llm_model_vision, llm_model_text):
    st.header("OWASP Vulnerability Details 📚")
    st.markdown("""
        Digite o CÓDIGO de uma categoria OWASP Top 10 (ex: `A03`) ou o NOME de uma falha específica (ex: `IDOR`, `XSS`, `SQL Injection`).
        O HuntIA fornecerá detalhes completos sobre a vulnerabilidade.
    """)
    logging.info("Página OWASP Vulnerability Details acessada.")

    # Bloco Universal de Verificação
    if not st.session_state.get('projeto_ativo_id') and not st.session_state.get('modo_rascunho'):
        st.error("Por favor, selecione um projeto ou ative o 'Modo Rascunho' na página de Configurações.")
        st.stop()
    
    if st.session_state.get('modo_rascunho'):
        st.info("Você está no Modo Rascunho. Esta consulta não será salva. ✏️")
    else:
        st.success(f"Consultando vulnerabilidades para o projeto: **{st.session_state.projeto_ativo_nome}**")
    st.markdown("---")

    # Initialize session state variables for this page
    if 'owasp_text_input_falha' not in st.session_state:
        st.session_state.owasp_text_input_falha = ""
    if 'owasp_text_analysis_result' not in st.session_state:
        st.session_state.owasp_text_analysis_result = ""
    if 'owasp_text_context_input' not in st.session_state:
        st.session_state.owasp_text_context_input = ""
    if 'owasp_text_consider_waf_state' not in st.session_state:
        st.session_state.owasp_consider_waf_state = False

    def reset_owasp_text_analysis():
        st.session_state.owasp_text_input_falha = ""
        st.session_state.owasp_text_analysis_result = ""
        st.session_state.owasp_text_context_input = ""
        st.session_state.owasp_consider_waf_state = False
        logging.info("OWASP Vulnerability Details: Reset de campos.")
        st.rerun()

    if st.button("Limpar e Fazer Nova Consulta", key="reset_text_analysis_button"):
        reset_owasp_text_analysis()

    user_input_falha = st.text_input(
        "Digite a falha ou categoria OWASP:",
        value=st.session_state.owasp_text_input_falha,
        placeholder="Ex: A01, Injection, IDOR, Cross-Site Scripting",
        key="text_input_falha"
    )
    st.session_state.owasp_text_input_falha = user_input_falha.strip()

    contexto_texto = st.text_area(
        "Contexto Adicional Livre (opcional, para refinar a falha específica):",
        value=st.session_state.owasp_text_context_input,
        placeholder="Ex: 'aplicação web em PHP', 'API REST com JWT', 'exploração via SQLi no parâmetro id'",
        height=150,
        key="text_context_input"
    )
    st.session_state.owasp_text_context_input = contexto_texto.strip()

    consider_waf_texto = st.checkbox(
        "Considerar bypass de WAF?",
        value=st.session_state.owasp_consider_waf_state,
        key="text_consider_waf_checkbox"
    )

    if st.button("Analisar Falha por Texto", key="analyze_text_button"):
        if not st.session_state.owasp_text_input_falha:
            st.error("Por favor, digite a falha ou categoria OWASP para análise.")
            logging.warning("OWASP Vulnerability Details: Análise abortada, entrada de falha vazia.")
            return
        else:
            categoria_owasp_codigo = None
            specific_vulnerability_name = st.session_state.owasp_text_input_falha

            if specific_vulnerability_name.upper() in OWASP_TOP_10_2021:
                categoria_owasp_codigo = specific_vulnerability_name.upper()
                st.info(f"Categoria OWASP selecionada: {OWASP_TOP_10_2021[categoria_owasp_codigo]}")
            else:
                categoria_owasp_codigo = mapear_falha_para_owasp(llm_model_text, specific_vulnerability_name)
                if categoria_owasp_codigo:
                    st.info(f"O LLM mapeou '{specific_vulnerability_name}' para a categoria OWASP: {OWASP_TOP_10_2021[categoria_owasp_codigo]}")
                else:
                    st.error("Não foi possível identificar a categoria OWASP para a falha fornecida.")
                    st.session_state.owasp_text_analysis_result = ""
                    return

            if categoria_owasp_codigo:
                with st.spinner(f"Obtendo informações para {specific_vulnerability_name}..."):
                    
                    global_context_prompt = get_global_context_prompt()
                    verbosity_prompt = get_verbosity_prompt()

                    prompt_base = (
                        f"Você é um especialista em segurança da informação e pentest."
                        f"{global_context_prompt}"
                        f"\n\n{verbosity_prompt}\n\n"
                        f"Sua tarefa é fornecer informações detalhadas para a vulnerabilidade **'{specific_vulnerability_name}'**,"
                        f"que se enquadra na categoria da OWASP Top 10 (2021) como **'{OWASP_TOP_10_2021[categoria_owasp_codigo]}' ({categoria_owasp_codigo})**."
                        f"Considere o seguinte contexto adicional livre: '{st.session_state.owasp_text_context_input}'."
                        f"\n\nPor favor, inclua os seguintes tópicos de forma **concisa, técnica e prática**, utilizando formato Markdown para títulos e blocos de código:"
                        f"\n\n## 1. Detalhamento da Falha"
                        f"\nExplique a natureza da vulnerabilidade de forma clara e concisa: o que ela é, como surge e por que é um problema de segurança. Foque nos conceitos essenciais e no seu mecanismo, **especificamente para '{specific_vulnerability_name}'**.\n"
                        f"\n\n## 2. Cenário de Exemplo de Exploração"
                        f"\nIlustre um cenário de ataque potencial que explora essa vulnerabilidade. Descreva as etapas passo a passo que um atacante poderia seguir para explorá-la, incluindo o ambiente típico e as condições necessárias para o sucesso do ataque, **aplicado a '{specific_vulnerability_name}'**. Não inclua código aqui, apenas a lógica.\n"
                        f"\n\n## 3. Severidade e Impacto Técnico"
                        f"\nClassifique a severidade desta vulnerabilidade: [Crítica/Alta/Média/Baixa].\n"
                        f"**Impacto Técnico Detalhado:** Descreva as **consequências técnicas diretas e específicas** da exploração desta falha, indo além do genérico. Ex: 'A execução desta SQL Injection pode resultar em exfiltração completa do banco de dados de usuários, comprometimento do servidor web subjacente (se Shell via SQLMap), e bypass de autenticação.'\n"
                        f"**CVSSv3.1 Score:** Forneça uma estimativa do score CVSS v3.1 para esta vulnerabilidade e o vetor CVSS. Ex: `7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)`\n"
                    )

                    if consider_waf_texto:
                         prompt_base += f"\n\n## 4. Dicas de Bypass de WAF"
                         prompt_base += f"\nForneça estratégias, técnicas e exemplos práticos (se aplicável à vulnerabilidade) para contornar ou evadir a detecção de um Web Application Firewall (WAF) ao tentar explorar esta falha. Inclua exemplos de payloads ou modificações de requisições que podem ajudar a testar o presença ou bypass do WAF."
                         solution_section_num = 5
                         benefits_risks_section_num = 6
                    else:
                         solution_section_num = 4
                         benefits_risks_section_num = 5

                    prompt_base += (
                        f"\n\n## {solution_section_num}. Detalhamento da Solução"
                        f"\nDescreva as **ações de correção concretas, detalhadas e com exemplos técnicos se possível**. Evite generalizações."
                        f"**Se o 'Contexto Adicional Livre' contém detalhes de exploração ou trechos de código, baseie suas dicas de solução diretamente nesse código ou nos princípios de exploração descritos, oferecendo correções coesas e precisas para aquele cenário específico.**"
                        f"Seja específico. Ex: 'Para mitigar SQL Injection, implemente Prepared Statements ou ORM's seguros (com exemplo de código em Python/Java), use validação de input rigorosa (whitelist) no backend, e aplique o princípio do menor privilégio ao usuário do banco de dados.'\n"
                        f"\n\n## {benefits_risks_section_num}. Benefícios e Riscos da Correção"
                        f"\nQuais são os benefícios de implementar a solução e os possíveis riscos ou impactos colaterais da sua aplicação?"
                        f"\n\nSeu objetivo é ser direto, útil e focado em ações e informações completas para um pentester, como um resumo para um relatório de pentest."
                    )

                    analysis_result = obter_resposta_llm(llm_model_text, [prompt_base])

                    if analysis_result:
                        st.session_state.owasp_text_analysis_result = analysis_result
                        logging.info("OWASP Vulnerability Details: Análise de texto concluída com sucesso.")

                        if not st.session_state.get('modo_rascunho', False):
                            try:
                                resumo_para_db = f"Consulta sobre a vulnerabilidade: '{st.session_state.owasp_text_input_falha}'"
                                database.salvar_analise(
                                    projeto_id=st.session_state.projeto_ativo_id,
                                    tipo_analise="OWASP Vulnerability Details",
                                    resumo_input=resumo_para_db,
                                    resultado_completo=analysis_result
                                )
                                st.toast("Consulta salva com sucesso no projeto!", icon="💾")
                            except Exception as e:
                                st.error(f"Houve um erro ao salvar a consulta no banco de dados: {e}")
                        else:
                            st.toast("Modo Rascunho: Resultado não salvo.", icon="✏️")
                    else:
                        st.session_state.owasp_text_analysis_result = "Não foi possível obter uma resposta do Gemini. Tente novamente."

    if st.session_state.owasp_text_analysis_result:
        st.subheader("Resultados da Análise por Texto")
        st.markdown(st.session_state.owasp_text_analysis_result)
        
        # --- INÍCIO DA CORREÇÃO: BOTÕES DE FEEDBACK RESTAURADOS ---
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="owasp_text_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback OWASP Vulnerability Details: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="owasp_text_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback OWASP Vulnerability Details: Precisa de Melhoria.")
        # --- FIM DA CORREÇÃO ---

# CÓDIGO DA NOVA PÁGINA PENTEST COPILOT

def pentest_copilot_page(llm_model_text):
    st.header("Pentest Copilot 🤖: Seu Assistente de Geração")
    st.markdown("""
        Seu centro de comando para gerar conteúdo tático. Selecione o que você precisa,
        forneça o contexto, e deixe o HuntIA construir para você.
    """)
    logging.info("Página Pentest Copilot acessada.")

    # Bloco Universal de Verificação
    if not st.session_state.get('projeto_ativo_id') and not st.session_state.get('modo_rascunho'):
        st.error("Por favor, selecione um projeto ou ative o 'Modo Rascunho' na página de Configurações.")
        st.stop()

    if st.session_state.get('modo_rascunho'):
        st.info("Você está no Modo Rascunho. O conteúdo gerado não será salvo. ✏️")
    else:
        st.success(f"Gerando conteúdo para o projeto: **{st.session_state.projeto_ativo_nome}**")
    st.markdown("---")

    # Inicializa o estado do seletor e do resultado
    if 'copilot_action' not in st.session_state:
        st.session_state.copilot_action = "Comando Tático de Ferramenta"
    if 'copilot_result' not in st.session_state:
        st.session_state.copilot_result = ""


    # Seletor principal da ferramenta
    action = st.selectbox(
        "O que você quer gerar?",
        ("Comando Tático de Ferramenta", "Prova de Conceito (PoC) em HTML", "Playbook de Pentest"),
        key="copilot_selector"
    )
    st.session_state.copilot_action = action
    
    st.markdown("---")
    
    # LÓGICA CONDICIONAL PARA CADA FERRAMENTA
    
    # ---------------------------------------------------------------------
    # 1. LÓGICA DO TACTICAL COMMAND ORCHESTRATOR
    # ---------------------------------------------------------------------
    if action == "Comando Tático de Ferramenta":
        st.subheader("Gerador de Comando Tático")
        
        scenario_input = st.text_area("Descreva o cenário e seu objetivo:", key="copilot_command_scenario", height=150)
        tool_options = ["Qualquer Ferramenta", "Nmap", "Metasploit", "Burp Suite (curl)", "SQLmap", "Hydra", "ffuf", "Nuclei"]
        selected_tool = st.selectbox("Ferramenta Preferida (Opcional):", options=tool_options, key="copilot_command_tool")
        os_options = ["Linux/macOS (Bash)", "Windows (PowerShell/CMD)"]
        selected_os = st.selectbox("Sistema Operacional Alvo:", options=os_options, key="copilot_command_os")

        if st.button("Gerar Comando", key="copilot_generate_command"):
            if scenario_input:
                with st.spinner("Gerando comando tático..."):
                    global_context_prompt = get_global_context_prompt()
                    verbosity_prompt = get_verbosity_prompt()
                    target_tool_text = f"Usando a ferramenta '{selected_tool}'." if selected_tool != "Qualquer Ferramenta" else ""
                    
                    command_prompt = (
                        f"Você é um especialista em pentest e automação."
                        f"{global_context_prompt}\n\n{verbosity_prompt}\n\n"
                        f"Sua tarefa é gerar um comando de linha de comando preciso e otimizado para o seguinte cenário:\n"
                        f"**Cenário do Usuário:** '{scenario_input}'.\n"
                        f"{target_tool_text}\n"
                        f"O comando deve ser para o sistema operacional '{selected_os}'."
                        f"\n\nForneça as seguintes informações em Markdown:\n\n"
                        f"## 1. Comando Sugerido\n"
                        f"Apresente o comando COMPLETO e PRONTO PARA USO em um bloco de código.\n\n"
                        f"## 2. Explicação do Comando\n"
                        f"Explique cada parte do comando e seus parâmetros.\n\n"
                        f"## 3. Observações de Segurança/Melhores Práticas\n"
                        f"Adicione quaisquer observações de segurança, riscos ou próximos passos."
                    )
                    
                    result = obter_resposta_llm(llm_model_text, [command_prompt])
                    st.session_state.copilot_result = result
                    
                    if result and not st.session_state.get('modo_rascunho', False):
                        database.salvar_analise(st.session_state.projeto_ativo_id, "Comando Tático", scenario_input, result)
                        st.toast("Comando salvo no projeto!", icon="💾")

    # ---------------------------------------------------------------------
    # 2. LÓGICA DO POC GENERATOR (HTML)
    # ---------------------------------------------------------------------
    elif action == "Prova de Conceito (PoC) em HTML":
        st.subheader("Gerador de PoC em HTML")

        vulnerability_input = st.text_input("Vulnerabilidade (Ex: CSRF, Clickjacking):", key="copilot_poc_vuln")
        context_input = st.text_area("Contexto Adicional (URL alvo, parâmetros, método, etc.):", key="copilot_poc_context", height=150)

        if st.button("Gerar PoC HTML", key="copilot_generate_poc"):
            if vulnerability_input:
                with st.spinner("Gerando PoC HTML..."):
                    global_context_prompt = get_global_context_prompt()
                    verbosity_prompt = get_verbosity_prompt()
                    
                    poc_prompt = (
                        f"Você é um especialista em pentest."
                        f"{global_context_prompt}\n\n{verbosity_prompt}\n\n"
                        f"Sua tarefa é gerar uma PoC em HTML funcional para a vulnerabilidade '{vulnerability_input}'.\n"
                        f"**Contexto:** {context_input if context_input else 'Nenhum.'}\n\n"
                        f"Forneça as informações nos seguintes tópicos:\n\n"
                        f"## 1. Detalhes da Vulnerabilidade e Como Funciona\n\n"
                        f"## 2. Código HTML da PoC (Completo e Mínimo)\n"
                        f"Encapsule o HTML completo em um bloco de código ` ```html `.\n\n"
                        f"## 3. Instruções de Uso e Payload (se aplicável)\n"
                    )
                    
                    result = obter_resposta_llm(llm_model_text, [poc_prompt])
                    st.session_state.copilot_result = result
                    
                    if result and not st.session_state.get('modo_rascunho', False):
                        database.salvar_analise(st.session_state.projeto_ativo_id, "PoC HTML", vulnerability_input, result)
                        st.toast("PoC salva no projeto!", icon="💾")

    # ---------------------------------------------------------------------
    # 3. LÓGICA DO PENTEST PLAYBOOK GENERATOR
    # ---------------------------------------------------------------------
    elif action == "Playbook de Pentest":
        st.subheader("Gerador de Playbook de Pentest")
        
        scope_input = st.text_area("Escopo do Pentest:", key="copilot_playbook_scope", height=100)
        objectives_input = st.text_area("Objetivos do Pentest:", key="copilot_playbook_objectives", height=100)

        if st.button("Gerar Playbook", key="copilot_generate_playbook"):
            if scope_input and objectives_input:
                with st.spinner("Gerando playbook..."):
                    global_context_prompt = get_global_context_prompt()
                    verbosity_prompt = get_verbosity_prompt()
                    
                    playbook_prompt = (
                         f"Você é um especialista em testes de intrusão."
                         f"{global_context_prompt}\n\n{verbosity_prompt}\n\n"
                         f"Sua tarefa é gerar um playbook detalhado para um pentest com o seguinte escopo e objetivos:\n"
                         f"**Escopo:** {scope_input}\n"
                         f"**Objetivos:** {objectives_input}\n\n"
                         f"O playbook deve cobrir as fases de Reconhecimento, Mapeamento, Análise de Vulnerabilidades, Exploração, e Geração de Relatório. Para cada fase, inclua Passos Chave, Ferramentas Sugeridas com comandos de exemplo, e Resultados Esperados."
                    )
                    
                    result = obter_resposta_llm(llm_model_text, [playbook_prompt])
                    st.session_state.copilot_result = result
                    
                    if result and not st.session_state.get('modo_rascunho', False):
                        database.salvar_analise(st.session_state.projeto_ativo_id, "Playbook de Pentest", scope_input, result)
                        st.toast("Playbook salvo no projeto!", icon="💾")

    # Exibe o resultado da ação do Copilot
    if 'copilot_result' in st.session_state and st.session_state.copilot_result:
        st.markdown("---")
        st.subheader("Resultado Gerado pelo Copilot")
        
        # Lógica para formatar a saída
        if st.session_state.copilot_action == "Prova de Conceito (PoC) em HTML":
             # Extrai o código HTML da resposta para renderização
             html_match = re.search(r"```html\n(.*?)```", st.session_state.copilot_result, re.DOTALL)
             if html_match:
                 html_code = html_match.group(1)
                 st.markdown("#### Visualização da PoC")
                 components.html(html_code, height=300, scrolling=True)
             st.markdown("#### Resposta Completa")
             st.markdown(st.session_state.copilot_result)
        else:
             st.markdown(st.session_state.copilot_result)

def http_request_analysis_page(llm_model_vision, llm_model_text):
    st.header("Deep HTTP Insight 📡")
    st.markdown("""
    Selecione o tipo de conteúdo para análise. Você pode colar:
    - **Requisição HTTP RAW:** Analisa requisições HTTP completas em busca de falhas OWASP.
    - **Headers de Resposta HTTP:** Analisa cabeçalhos de resposta para misconfigurations e exposição de informações.
    - **Configuração de Servidor:** Analisa trechos de configuração de servidores (Apache, Nginx, IIS) para hardening.
    """)

    # Inicializar variáveis de sessão
    if 'http_analysis_type' not in st.session_state:
        st.session_state.http_analysis_type = "Requisição HTTP RAW"
    if 'http_request_input_url' not in st.session_state:
        st.session_state.http_request_input_url = ""
    if 'http_analysis_content' not in st.session_state:
        st.session_state.http_analysis_content = ""
    if 'http_analysis_result' not in st.session_state:
        st.session_state.http_analysis_result = ""
    if 'http_analysis_summary' not in st.session_state:
        st.session_state.http_analysis_summary = None
    if 'http_context_free_input' not in st.session_state:
        st.session_state.http_context_free_input = ""

    logging.info("Página Deep HTTP Insight acessada.")

    # Resetar campos se necessário
    def reset_http_analysis():
        st.session_state.http_analysis_type = "Requisição HTTP RAW"
        st.session_state.http_request_input_url = ""
        st.session_state.http_analysis_content = ""
        st.session_state.http_analysis_result = ""
        st.session_state.http_analysis_summary = None
        st.session_state.http_context_free_input = ""
        logging.info("Deep HTTP Insight: Reset de campos.")
        st.rerun()

    # Botão para limpar e fazer nova consulta
    if st.button("Limpar e Fazer Nova Consulta", key="reset_http_analysis_button"):
        reset_http_analysis()

    # Selecionar tipo de análise
    analysis_type_options = [
        "Requisição HTTP RAW",
        "Headers de Resposta HTTP",
        "Configuração de Servidor (Apache/Nginx/IIS)"
    ]
    st.session_state.http_analysis_type = st.radio(
        "Tipo de Análise:",
        options=analysis_type_options,
        key="http_analysis_type_radio"
    )

    # URL alvo (apenas para Requisição HTTP RAW)
    if st.session_state.http_analysis_type == "Requisição HTTP RAW":
        st.session_state.http_request_input_url = st.text_input(
            "URL Alvo (Target):",
            value=st.session_state.http_request_input_url,
            placeholder="Exemplo: https://example.com/path "
        )
        if not st.session_state.http_request_input_url:
            st.error("Por favor, forneça a URL Alvo para a Requisição HTTP RAW.")
            logging.warning("Deep HTTP Insight: Análise de Requisições HTTP abortada, URL Alvo vazia.")
            return

    # Conteúdo para análise
    content_placeholder = (
        "- Para **Requisição HTTP RAW**: Cole aqui a requisição completa.\n"
        "- Para **Headers de Resposta HTTP**: Cole apenas os headers.\n"
        "- Para **Configuração de Servidor**: Cole o trecho de configuração."
    )
    st.session_state.http_analysis_content = st.text_area(
        f"Cole o conteúdo para análise aqui ({st.session_state.http_analysis_type}):",
        value=st.session_state.http_analysis_content,
        placeholder=content_placeholder,
        height=300,
        key="http_config_input_area"
    )
    if not st.session_state.http_analysis_content.strip():
        st.error("Por favor, cole o conteúdo para análise.")
        logging.warning("Deep HTTP Insight: Análise abortada, conteúdo vazio.")
        return

    # Contexto adicional livre
    st.session_state.http_context_free_input = st.text_area(
        "Contexto Adicional Livre (opcional, para detalhes de exploração ou trechos de código):",
        value=st.session_state.http_context_free_input,
        placeholder=(
            "Ex: 'A exploração foi feita injetando `'; OR 1=1--` no parâmetro `id` da URL.', "
            "'Trecho de código: `user_id = request.args.get('id')`'"
        ),
        height=100,
        key="http_context_free_input_area"
    )

    # Botão para analisar
    if st.button("Analisar Conteúdo", key="analyze_http_content_button"):
        with st.spinner(f"Analisando {st.session_state.http_analysis_type} com LLM..."):
            # Preparar o prompt baseado no tipo de análise
            global_context_prompt = get_global_context_prompt()
            escaped_http_context_free_input = st.session_state.http_context_free_input.replace('{', '{{').replace('}', '}}')

            if st.session_state.http_analysis_type == "Requisição HTTP RAW":
                prompt_intro_context = (
                    "Você é um especialista em segurança da informação e pentest." +
                    global_context_prompt +
                    f"Analise a requisição HTTP RAW fornecida e a URL alvo '{st.session_state.http_request_input_url}'. Identifique **TODAS as possíveis falhas de segurança OWASP Top 10 (2021) e outras vulnerabilidades relevantes aplicáveis**, sendo extremamente detalhado e preciso na análise de cada parte da requisição. "
                )
                code_lang = "http"

                # Parsear a requisição HTTP RAW
                parsed_req = parse_raw_http_request(st.session_state.http_analysis_content)
                prompt_content_for_llm = (
                    f"URL Alvo: {st.session_state.http_request_input_url}\n"
                    f"Método: {parsed_req['method']}\n"
                    f"Caminho: {parsed_req['path']}\n"
                    f"Headers:\n{json.dumps(parsed_req['headers'], indent=2).replace('{', '{{').replace('}', '}}')}\n"
                    f"Corpo:\n{parsed_req['body'].replace('{', '{{').replace('}', '}}')}\n"
                    f"Requisição RAW Original:\n{st.session_state.http_analysis_content.replace('{', '{{').replace('}', '}}')}"
                )

            elif st.session_state.http_analysis_type == "Headers de Resposta HTTP":
                prompt_intro_context = (
                    "Você é um especialista em segurança web e análise de headers HTTP." +
                    global_context_prompt +
                    "Analise os seguintes headers de resposta HTTP. Identifique misconfigurations de segurança, exposição de informações sensíveis e a falta de headers de segurança importantes. Priorize a descrição do achado e o exemplo de impacto."
                )
                code_lang = "http"
                prompt_content_for_llm = st.session_state.http_analysis_content.replace('{', '{{').replace('}', '}}')

            elif st.session_state.http_analysis_type == "Configuração de Servidor (Apache/Nginx/IIS)":
                prompt_intro_context = (
                    "Você é um especialista em hardening de servidores web (Apache, Nginx, IIS) e pentest." +
                    global_context_prompt +
                    "\n\nAnalise o seguinte trecho de configuração de servidor. Identifique misconfigurations de segurança (OWASP A05), diretórios expostos, e outras vulnerabilidades. Priorize a descrição do achado e o exemplo de impacto."
                )
                code_lang = "plaintext"
                prompt_content_for_llm = st.session_state.http_analysis_content.replace('{', '{{').replace('}', '}}')

            # Montar o prompt completo
            full_prompt = (
                prompt_intro_context +
                f"\n\n**RESUMO:** Forneça um resumo quantitativo na PRIMEIRA LINHA da sua resposta, no formato exato: `Total de Achados: X | Críticos: Y | Altos: Z | Médios: W | Baixos: V` (substitua X,Y,Z,W,V pelos números correspondentes). Se não houver achados, use 0.\n\n"
                f"**Conteúdo para análise:**\n"
                f"```{code_lang}\n{prompt_content_for_llm}\n```\n\n"
                f"Para cada **achado de segurança (vulnerabilidade ou misconfiguration)** identificado, apresente os seguintes tópicos de forma separada e concisa, utilizando Markdown. **Comece cada achado com um cabeçalho `###`:**\n\n"
                f"### [Tipo de Achado] (Ex: Header de Segurança Ausente, Versão do Servidor Exposta)\n"
                f"**Categoria OWASP (se aplicável):** [Ex: A05: Security Misconfiguration]. Se não OWASP, indique 'Exposição de Informação' ou 'Melhoria de Hardening'.\n"
                f"**Severidade/Risco:** [Crítica/Alta/Média/Baixa/Informativo - explique o impacto deste achado específico]\n"
                f"**Detalhes no Conteúdo:** Explique onde no conteúdo fornecido a falha foi observada. Cite o trecho relevante da requisição/configuração. Seja preciso na correlação.\n"
                f"**Exemplo de Exploração:** Descreva o risco e como um atacante poderia se beneficiar desta configuração/vulnerabilidade. Forneça um comando simples, um payload ou uma explicação de como testar/explorar. **Se o 'Contexto Adicional Livre' (fornecido pelo usuário) contém detalhes de um PoC ou trechos de código de exploração, baseie seu exemplo diretamente nele, incluindo o código/comando relevante em um bloco de código Markdown (` ```{code_lang} ` ou ` ```bash ` ou ` ```http `).** Se o contexto livre for irrelevante ou não tiver PoC, forneça um exemplo genérico e aplicável. Não se preocupe com \"Recomendação/Mitigação\" ou \"Ferramentas Sugeridas\" separadamente.\n"
                f"--- (Fim do Achado) ---"  # Separador para o próximo achado
            )

            # Obter resposta do LLM
            analysis_result = obter_resposta_llm(llm_model_text, [full_prompt])
            if analysis_result:
                st.session_state.http_analysis_result = analysis_result
                logging.info("Deep HTTP Insight: Análise concluída com sucesso.")
            else:
                st.session_state.http_analysis_result = "Não foi possível obter uma resposta do LLM. Tente novamente."
                logging.error("Deep HTTP Insight: Falha na obtenção da resposta do LLM.")

            # Parsear o resumo
            if st.session_state.http_analysis_result:
                summary_match = re.search(
                    r'Total de Achados:\s*(\d+)\s*\|\s*Críticos:\s*(\d+)\s*\|\s*Altos:\s*(\d+)\s*\|\s*Médios:\s*(\d+)\s*\|\s*Baixos:\s*(\d+)',
                    st.session_state.http_analysis_result
                )
                if summary_match:
                    total, criticos, altos, medios, baixos = map(int, summary_match.groups())
                    st.session_state.http_analysis_summary = {
                        "Total": total,
                        "Críticas": criticos,
                        "Altas": altos,
                        "Médios": medios,
                        "Baixos": baixos
                    }
                else:
                    st.session_state.http_analysis_summary = {"Total": 0, "Críticas": 0, "Altas": 0, "Médios": 0, "Baixos": 0}
                    logging.warning("Deep HTTP Insight: Resumo de vulnerabilidades não encontrado na resposta do LLM.")

    # Exibir resultados
    if st.session_state.http_analysis_result:
        st.subheader("Resultados da Análise de Segurança")

        # Exibir métricas
        if st.session_state.http_analysis_summary:
            cols = st.columns(5)
            cols[0].metric("Total", st.session_state.http_analysis_summary.get("Total", 0))
            cols[1].metric("Críticos", st.session_state.http_analysis_summary.get("Críticas", 0))
            cols[2].metric("Altos", st.session_state.http_analysis_summary.get("Altas", 0))
            cols[3].metric("Médios", st.session_state.http_analysis_summary.get("Médios", 0))
            cols[4].metric("Baixos", st.session_state.http_analysis_summary.get("Baixos", 0))

        # Exibir detalhes das vulnerabilidades
        st.markdown(st.session_state.http_analysis_result)

        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="http_analysis_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback Deep HTTP Insight: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="http_analysis_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback Deep HTTP Insight: Precisa de Melhoria.")

    logging.info("Página Deep HTTP Insight finalizada.")

def pentest_lab_page(llm_model_vision, llm_model_text):
    st.header("Pentest Lab: Seu Laboratório de Vulnerabilidades 🧪")
    st.markdown("""
        Selecione uma vulnerabilidade e o HuntIA irá gerar um mini-laboratório HTML básico (PoC em HTML) para que você possa testar a falha diretamente no seu navegador.
        También fornecerá dicas de como explorar e o payload/comando para o teste.
        **AVISO: Este laboratório é para fins educacionais e de teste. Não execute payloads em sites reais.**
    """)
    logging.info("Página Pentest Lab acessada.")

    # Initialize session state variables for this page
    if 'lab_vulnerability_selected' not in st.session_state:
        st.session_state.lab_vulnerability_selected = None
    if 'lab_html_poc' not in st.session_state:
        st.session_state.lab_html_poc = ""
    if 'lab_explanation' not in st.session_state:
        st.session_state.lab_explanation = ""
    if 'lab_payload_example' not in st.session_state:
        st.session_state.lab_payload_example = ""

    def reset_pentest_lab():
        st.session_state.lab_vulnerability_selected = None
        st.session_state.lab_html_poc = ""
        st.session_state.lab_explanation = ""
        st.session_state.lab_payload_example = ""
        logging.info("Pentest Lab: Reset de campos.")
        st.rerun()

    if st.button("Limpar Laboratório", key="reset_lab_button"):
        reset_pentest_lab()

    vulnerability_options = ["Escolha uma vulnerabilidade"] + sorted(OWASP_SUBCATEGORIES["A03"])

    selected_vuln = st.selectbox(
        "Selecione a vulnerabilidade para o laboratório:",
        options=vulnerability_options,
        index=0,
        key="lab_vuln_select"
    )
    st.session_state.lab_vulnerability_selected = selected_vuln if selected_vuln != "Escolha uma vulnerabilidade" else None

    if st.button("Gerar Laboratório", key="generate_lab_button"):
        if not st.session_state.lab_vulnerability_selected:
            st.error("Por favor, selecione uma vulnerabilidade para gerar o laboratório.")
            logging.warning("Pentest Lab: Geração abortada, nenhuma vulnerabilidade selecionada.")
            return
        else:
            with st.spinner(f"Gerando laboratório para {st.session_state.lab_vulnerability_selected}..."):
                logging.info(f"Pentest Lab: Gerando laboratório para {st.session_state.lab_vulnerability_selected}.")

                # Contexto global é injetado aqui
                global_context_prompt = get_global_context_prompt()

                lab_prompt = (
                    f"Você é um especialista em pentest e educador."
                    f"{global_context_prompt}" # INJETANDO CONTEXTO GLOBAL
                    f"\n\nSua tarefa é criar um mini-laboratório HTML simples e um payload para demonstrar a vulnerabilidade '{st.session_state.lab_vulnerability_selected}'.\n"
                    f"\nForneça as informações nos seguintes tópicos:\n\n"
                    f"## 1. Descrição da Vulnerabilidade e Dicas de Exploração\n"
                    f"Uma breve explicação do que é a vulnerabilidade, como ela funciona e dicas práticas de como tentar explorá-la.\n\n"
                    f"## 2. Mini-Laboratório HTML (PoC HTML)\n"
                    f"Forneça um **código HTML COMPLETO e MÍNIMO** (com tags `<html>`, `<head>`, `<body>`) que simule um cenário vulnerável a **{st.session_state.lab_vulnerability_selected}**.\n"
                    f"Este HTML deve ser funcional e auto-contido. O foco é na vulnerabilidade, não no design.\n"
                    f"Encapsule o HTML completo em um bloco de código Markdown com a linguagem `html` (` ```html `).\n\n"
                    f"## 3. Exemplo de Payload/Comando para Teste\n"
                    f"Forneça o payload ou comando específico que o usuário injetaria ou usaria neste HTML para provar a vulnerabilidade. Encapsule em um bloco de código Markdown com la linguagem apropriada (ex: ` ```js `, ` ```sql `, ` ```bash `).\n"
                    f"Este payload deve ser adaptado para o HTML gerado no PoC HTML.\n"
                    f"\nSeja didático e direto. O objetivo é que o usuário possa copiar e colar o HTML e o payload para testar."
                )

                lab_generation_raw = obter_resposta_llm(llm_model_text, [lab_prompt])

                if lab_generation_raw:
                    st.session_state.lab_explanation = lab_generation_raw

                    html_start = lab_generation_raw.find("```html")
                    html_end = lab_generation_raw.find("```", html_start + len("```html"))

                    payload_start_marker = "```"

                    if html_start != -1 and html_end != -1:
                        payload_start = lab_generation_raw.find(payload_start_marker, html_end + 1)
                    else:
                        payload_start = lab_generation_raw.find(payload_start_marker)

                    payload_end = -1
                    if payload_start != -1:
                        payload_end = lab_generation_raw.find(payload_start_marker, payload_start + len(payload_start_marker))
                        if payload_end == payload_start:
                            payload_end = -1

                    if html_start != -1 and html_end != -1:
                        st.session_state.lab_html_poc = lab_generation_raw[html_start + len("```html") : html_end].strip()
                    else:
                        st.session_state.lab_html_poc = "Não foi possível extrair o HTML do laboratório. Verifique a resposta do LLM."
                        logging.warning("Pentest Lab: HTML não extraído da resposta do LLM.")

                    if payload_start != -1 and payload_end != -1:
                        payload_content = lab_generation_raw[payload_start + len(payload_start_marker) : payload_end].strip()
                        if '\n' in payload_content and payload_content.splitlines()[0].strip().isalpha():
                            st.session_state.lab_payload_example = '\n'.join(payload_content.splitlines()[1:])
                        else:
                            st.session_state.lab_payload_example = payload_content
                        logging.info("Pentest Lab: Laboratório gerado com sucesso.")
                    else:
                        st.session_state.lab_payload_example = "Não foi possível extrair o exemplo de payload. Verifique a resposta do LLM."
                        logging.warning("Pentest Lab: Payload não extraído da resposta do LLM.")
                else:
                    st.session_state.lab_explanation = "Não foi possível gerar o laboratório para a vulnerabilidade selecionada."
                    st.session_state.lab_html_poc = ""
                    st.session_state.lab_payload_example = ""
                    logging.error("Pentest Lab: Falha na geração do laboratório pelo LLM.")

    if st.session_state.lab_html_poc or st.session_state.lab_explanation:
        st.subheader("Resultados do Laboratório")

        st.markdown(st.session_state.lab_explanation)

        if st.session_state.lab_html_poc:
            st.markdown("#### Mini-Laboratório HTML (Copie e Cole em um arquivo .html e abra no navegador)")
            st.code(st.session_state.lab_html_poc, language="html")

            st.markdown("---")
            st.markdown("#### Teste o Laboratório Aqui (Visualização Direta)")
            st.warning("AVISO: Esta visualização direta é para conveniência. Para um teste real e isolado, **salve o HTML em um arquivo .html e abra-o diretamente no seu navegador**.")
            components.html(st.session_state.lab_html_poc, height=300, scrolling=True)
            st.markdown("---")

        if st.session_state.lab_payload_example: # Usando lab_payload_example pois é o que está em session_state para esta página
            st.markdown("#### Exemplo de Payload/Comando para Teste")
            payload_lang = "plaintext"
            first_line = st.session_state.lab_payload_example.splitlines()[0].strip() if st.session_state.lab_payload_example else ""

            if "alert(" in st.session_state.lab_payload_example.lower() or "document.write" in st.session_state.lab_payload_example.lower():
                payload_lang = "js"
            elif "SELECT " in st.session_state.lab_payload_example.upper() and "FROM " in st.session_state.lab_payload_example.upper():
                payload_lang = "sql"
            elif "http" in first_line.lower() and ("post" in first_line.lower() or "get" in first_line.lower()):
                payload_lang = "http"
            elif "curl " in first_line.lower() or "bash" in first_line.lower():
                payload_lang = "bash"
            elif "python" in first_line.lower() or "import" in st.session_state.lab_payload_example.lower():
                payload_lang = "python"

            st.code(st.session_state.lab_payload_example, language=payload_lang)
        
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="pentest_lab_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback Pentest Lab: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="pentest_lab_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback Pentest Lab: Precisa de Melhoria.")

# Substitua sua função static_code_analyzer_page por esta versão melhorada

def static_code_analyzer_page(llm_model_text):
    st.header("👨‍💻 Static Code & Secret Analyzer (com TruffleHog)")
    st.markdown("""
    Cole um trecho de código para análise. A ferramenta usará o **TruffleHog** para uma varredura precisa de segredos
    e, em seguida, a IA pode ser usada para analisar os riscos e as mitigações.
    """)
    logging.info("Página Static Code Analyzer com TruffleHog acessada.")

    if 'code_input_content' not in st.session_state:
        st.session_state.code_input_content = ""
    if 'trufflehog_results' not in st.session_state:
        st.session_state.trufflehog_results = []
    if 'llm_secret_analysis' not in st.session_state:
        st.session_state.llm_secret_analysis = ""

    code_content = st.text_area(
        "Cole o conteúdo para análise aqui:",
        placeholder="const-apiKey = 'sk_live_xxxxxxxx...';\n\nfetch('/api/data');",
        height=300,
        key="secret_code_input"
    )

    if st.button("🔎 Analisar Segredos com TruffleHog"):
        st.session_state.trufflehog_results = []
        st.session_state.llm_secret_analysis = ""

        if code_content.strip():
            with st.spinner("Executando TruffleHog..."):
                # Cria um arquivo temporário para o TruffleHog analisar
                with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.tmp') as tmp_file:
                    tmp_file.write(code_content)
                    tmp_file_path = tmp_file.name

                try:
                    # Executa o TruffleHog como um subprocesso, capturando a saída JSON
                    command = ["trufflehog", "filesystem", tmp_file_path, "--json"]
                    result = subprocess.run(command, capture_output=True, text=True, check=True)

                    # Processa cada linha da saída JSON
                    findings = []
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            findings.append(json.loads(line))

                    st.session_state.trufflehog_results = findings
                    logging.info(f"TruffleHog encontrou {len(findings)} segredos.")

                except subprocess.CalledProcessError as e:
                    # Se o TruffleHog não encontrar nada, ele pode sair com um código de erro.
                    # Verificamos se há saída para ter certeza de que não é um erro real.
                    if e.stdout:
                         findings = []
                         for line in e.stdout.strip().split('\n'):
                             if line:
                                 findings.append(json.loads(line))
                         st.session_state.trufflehog_results = findings
                         logging.info(f"TruffleHog encontrou {len(findings)} segredos (com exit code).")
                    else:
                        st.error(f"Erro ao executar o TruffleHog: {e.stderr}")
                        logging.error(f"TruffleHog stderr: {e.stderr}")

                except FileNotFoundError:
                    st.error("Comando 'trufflehog' não encontrado. Você o instalou no seu ambiente? (Execute: pip install trufflehog)")
                except Exception as e:
                    st.error(f"Ocorreu um erro inesperado: {e}")
                finally:
                    # Limpa o arquivo temporário
                    os.remove(tmp_file_path)
        else:
            st.warning("Por favor, insira um conteúdo para analisar.")

    if st.session_state.trufflehog_results:
        st.subheader("Resultados da Análise do TruffleHog")
        total_findings = len(st.session_state.trufflehog_results)
        st.success(f"✅ Análise concluída! Foram encontrados {total_findings} segredos potenciais.")

        for i, finding in enumerate(st.session_state.trufflehog_results):
            with st.expander(f"Segredo #{i+1}: {finding.get('DetectorName', 'N/A')}"):
                st.code(finding.get('Raw', ''), language='text')
                st.write(f"**Linha:** {finding.get('LineNum', 'N/A')}")
                st.write(f"**Verificado:** {'Sim' if finding.get('Verified') else 'Não'}")

        # Botão para análise com IA
        if st.button("🤖 Analisar Riscos e Correções com IA"):
            with st.spinner("A IA está analisando os segredos encontrados..."):
                findings_json = json.dumps(st.session_state.trufflehog_results, indent=2)

                analysis_prompt = f"""
                Você é um especialista em segurança de aplicações (AppSec).
                A ferramenta TruffleHog encontrou os seguintes segredos expostos em um trecho de código.

                **Resultados do TruffleHog (JSON):**
                ```json
                {findings_json}
                ```

                Sua tarefa é criar um relatório conciso sobre estes achados. Para cada segredo encontrado, forneça:
                1.  **Análise do Risco:** Qual o impacto real se este segredo for explorado? (Ex: Acesso não autorizado, movimentação lateral, custos financeiros).
                2.  **Plano de Remediação:** Quais são os passos exatos para corrigir esta falha? (Ex: 1. Invalidar o segredo exposto. 2. Remover do código-fonte e do histórico do Git. 3. Mover para uma variável de ambiente ou um cofre de segredos como HashiCorp Vault ou AWS Secrets Manager).

                Formate a saída de forma clara usando Markdown.
                """
                st.session_state.llm_secret_analysis = obter_resposta_llm(llm_model_text, [analysis_prompt])

    elif st.session_state.get('trufflehog_results') == []:
         st.info("Nenhum segredo foi encontrado pelo TruffleHog no conteúdo fornecido.")


    if st.session_state.llm_secret_analysis:
        st.subheader("Análise de Risco e Remediação (IA)")
        st.markdown(st.session_state.llm_secret_analysis)

          # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="code_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback OpenAPI Analyzer: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="swagger_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback OpenAPI Analyzer: Precisa de Melhoria.")

def static_code_analyzer_page(llm_model_text):
    st.header("👨‍💻 Static Code & Secret Analyzer (com TruffleHog v3)")
    st.markdown("""
    Cole um trecho de código para análise. A ferramenta usará o **TruffleHog v3** para uma varredura precisa de segredos
    e, em seguida, a IA pode ser usada para analisar os riscos e as mitigações.
    """)
    logging.info("Página Static Code Analyzer com TruffleHog acessada.")

    # --- INÍCIO DA CORREÇÃO ---

    # Função para limpar o estado da página
    def reset_secret_analyzer():
        st.session_state.code_input_content = ""
        st.session_state.trufflehog_results = []
        st.session_state.llm_secret_analysis = ""
        logging.info("Static Code Analyzer: Campos e resultados limpos.")

    # Botão para limpar e fazer nova consulta
    if st.button("Limpar e Nova Análise", key="clear_secrets_button"):
        reset_secret_analyzer()
        st.rerun() # Recarrega a página para refletir a limpeza

    # --- FIM DA CORREÇÃO ---

    if 'code_input_content' not in st.session_state:
        st.session_state.code_input_content = ""
    if 'trufflehog_results' not in st.session_state:
        st.session_state.trufflehog_results = []
    if 'llm_secret_analysis' not in st.session_state:
        st.session_state.llm_secret_analysis = ""

    # Usamos a chave 'secret_code_input' para o st.text_area para que ele seja atualizado pelo reset
    code_content = st.text_area(
        "Cole o conteúdo para análise aqui:",
        value=st.session_state.get('code_input_content', ''), # Usamos .get() para segurança
        placeholder="const apiKey = 'sk_live_xxxxxxxx...';\n\nfetch('/api/data');",
        height=300,
        key="secret_code_text_area"
    )
    st.session_state.code_input_content = code_content


    if st.button("🔎 Analisar Segredos com TruffleHog"):
        st.session_state.trufflehog_results = []
        st.session_state.llm_secret_analysis = ""

        if code_content.strip():
            with st.spinner("Executando TruffleHog v3..."):
                with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.tmp') as tmp_file:
                    tmp_file.write(code_content)
                    tmp_file_path = tmp_file.name

                try:
                    python_executable_path = sys.executable
                    trufflehog_executable_path = os.path.join(os.path.dirname(python_executable_path), 'trufflehog')

                    # Verificamos se o executável existe no venv antes de tentar o PATH global
                    if not os.path.exists(trufflehog_executable_path):
                        trufflehog_executable_path = "trufflehog" # Recorre ao PATH global (instalado via Brew)

                    command = [trufflehog_executable_path, "filesystem", tmp_file_path, "--json"]
                    
                    result = subprocess.run(command, capture_output=True, text=True)
                    
                    findings = []
                    if result.stdout:
                        for line in result.stdout.strip().split('\n'):
                            if line:
                                findings.append(json.loads(line))
                    
                    st.session_state.trufflehog_results = findings
                    logging.info(f"TruffleHog encontrou {len(findings)} segredos.")

                except FileNotFoundError:
                    st.error("Comando 'trufflehog' não encontrado. Você o instalou com o Homebrew ou no seu venv? (Execute: brew install trufflehog)")
                except Exception as e:
                    st.error(f"Ocorreu um erro inesperado: {e}")
                finally:
                    os.remove(tmp_file_path)
        else:
            st.warning("Por favor, insira um conteúdo para analisar.")

    # Exibição dos resultados (lógica inalterada)
    if st.session_state.trufflehog_results:
        st.subheader("Resultados da Análise do TruffleHog")
        total_findings = len(st.session_state.trufflehog_results)
        st.success(f"✅ Análise concluída! Foram encontrados {total_findings} segredos potenciais.")

        for i, finding in enumerate(st.session_state.trufflehog_results):
            with st.expander(f"Segredo #{i+1}: {finding.get('Detector', {}).get('Name', 'N/A')}"):
                st.code(finding.get('Raw', ''), language='text')
                st.write(f"**Verificado:** {'Sim' if finding.get('Verified') else 'Não'}")

        if st.button("🤖 Analisar Riscos e Correções com IA"):
            with st.spinner("A IA está analisando os segredos encontrados..."):
                findings_json = json.dumps(st.session_state.trufflehog_results, indent=2)
                analysis_prompt = f"""
                Você é um especialista em segurança de aplicações (AppSec).
                A ferramenta TruffleHog encontrou os seguintes segredos expostos. Analise o risco de cada um e forneça um plano de remediação detalhado.
                **Resultados (JSON):**
                ```json
                {findings_json}
                ```
                """
                st.session_state.llm_secret_analysis = obter_resposta_llm(llm_model_text, [analysis_prompt])

    elif st.session_state.get('trufflehog_results') == []:
         st.info("Nenhum segredo foi encontrado pelo TruffleHog no conteúdo fornecido.")

    if st.session_state.llm_secret_analysis:
        st.subheader("Análise de Risco e Remediação (IA)")
        st.markdown(st.session_state.llm_secret_analysis)

        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="swagger_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback OpenAPI Analyzer: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="swagger_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback OpenAPI Analyzer: Precisa de Melhoria.")


def tactical_command_orchestrator_page(llm_model_text):
    st.header("Tactical Command Orchestrator 🤖")
    st.markdown("""
        Descreva o seu cenário de pentest, o alvo, e qual ferramenta ou tipo de ação você precisa.
        O HuntIA irá sugerir os comandos mais eficazes e otimizados, adaptados ao seu ambiente e objetivo.
    """)
    logging.info("Página Tactical Command Orchestrator acessada.")

    if 'command_scenario_input' not in st.session_state:
        st.session_state.command_scenario_input = ""
    if 'command_analysis_result' not in st.session_state:
        st.session_state.command_analysis_result = ""
    if 'command_tool_selection' not in st.session_state:
        st.session_state.command_tool_selection = "Qualquer Ferramenta"
    if 'command_os_selection' not in st.session_state:
        st.session_state.command_os_selection = "Linux/macOS (Bash)"

    def reset_command_orchestrator():
        st.session_state.command_scenario_input = ""
        st.session_state.command_analysis_result = ""
        st.session_state.command_tool_selection = "Qualquer Ferramenta"
        st.session_state.command_os_selection = "Linux/macOS (Bash)"
        logging.info("Tactical Command Orchestrator: Reset de campos.")
        st.rerun()

    if st.button("Limpar Orquestrador", key="reset_command_orchestrator_button"):
        reset_command_orchestrator()

    scenario_input = st.text_area(
        "Descreva o cenário e seu objetivo (Ex: 'Preciso de um comando Nmap para escanear portas UDP em 192.168.1.100', 'Como faço um brute-force de login em um formulário web com Hydra?'):",
        value=st.session_state.command_scenario_input,
        placeholder="Ex: Escanear portas TCP em um host, encontrar diretórios ocultos, criar payload de shell reverso.",
        height=150,
        key="command_scenario_input_area"
    )
    st.session_state.command_scenario_input = scenario_input.strip()

    tool_options = [
        "Qualquer Ferramenta", "Nmap", "Metasploit", "Burp Suite (comandos curl/HTTP)",
        "SQLmap", "Hydra", "ffuf", "Nuclei", "Subfinder", "Httpx", "Wpscan", "Other"
    ]
    selected_tool = st.selectbox(
        "Ferramenta Preferida (Opcional):",
        options=tool_options,
        index=tool_options.index(st.session_state.command_tool_selection),
        key="command_tool_select"
    )
    st.session_state.command_tool_selection = selected_tool

    os_options = ["Linux/macOS (Bash)", "Windows (PowerShell/CMD)"]
    selected_os = st.selectbox(
        "Sistema Operacional para o Comando:",
        options=os_options,
        index=os_options.index(st.session_state.command_os_selection),
        key="command_os_select"
    )
    st.session_state.command_os_selection = selected_os

    if st.button("Gerar Comando Tático", key="generate_command_button"):
        if not st.session_state.command_scenario_input:
            st.error("Por favor, descreva o cenário para gerar o comando.")
            logging.warning("Tactical Command Orchestrator: Geração abortada, cenário vazio.")
            return
        else:
            with st.spinner("Gerando comando tático otimizado..."):
                logging.info(f"Tactical Command Orchestrator: Gerando comando para cenário '{st.session_state.command_scenario_input}'.")
                target_tool_text = f"Usando a ferramenta '{st.session_state.command_tool_selection}'." if st.session_state.command_tool_selection != "Qualquer Ferramenta" else ""
                target_os_text = f"O comando deve ser para o sistema operacional '{st.session_state.command_os_selection}'."
                
                # --- INJETANDO O CONTEXTO GLOBAL ---
                global_context_prompt = get_global_context_prompt()
                # --- FIM INJEÇÃO DE CONTEXTO ---


                command_prompt = (
                    f"Você é um especialista em pentest e automação, com vasto conhecimento em ferramentas de linha de comando. "
                    f"{global_context_prompt}" # INJETANDO CONTEXTO GLOBAL
                    f"\n\nSua tarefa é gerar um comando de linha de comando preciso e otimizado para o seguinte cenário:\n"
                    f"**Cenário do Usuário:** '{st.session_state.command_scenario_input}'.\n"
                    f"{target_tool_text}\n"
                    f"{target_os_text}"
                    f"\n\nForneça as seguintes informações em Markdown:\n\n"
                    f"## 1. Comando Sugerido\n"
                    f"Apresente o comando COMPLETO e PRONTO PARA USO. Encapsule-o em um bloco de código Markdown (` ```bash `, ` ```powershell `, ` ```cmd ` ou similar, de acordo com o OS). "
                    f"Inclua todos os parâmetros necessários e exemplos de placeholder (ex: `<IP_ALVO>`, `<USUARIO>`, `<SENHA_LIST>`).\n\n"
                    f"## 2. Explicação do Comando\n"
                    f"Explique cada parte do comando, seus parâmetros e por que ele é eficaz para o cenário. Detalhe como o usuário pode adaptá-lo.\n\n"
                    f"## 3. Observações de Segurança/Melhores Práticas\n"
                    f"Adicione quaisquer observações de segurança, como a necessidade de autorização, riscos potenciais, ou considerações sobre o ambiente (ex: firewalls, WAFs). Sugira variações ou próximos passos.\n\n"
                    f"Seu objetivo é ser extremamente prático, útil e direto. Se o cenário for inviável ou muito genérico, explique por que e sugira um refinamento."
                )

                command_result_raw = obter_resposta_llm(llm_model_text, [command_prompt])

                if command_result_raw:
                    st.session_state.command_analysis_result = command_result_raw
                    logging.info("Tactical Command Orchestrator: Comando gerado com sucesso.")
                else:
                    st.session_state.command_analysis_result = "Não foi possível gerar o comando. Tente refinar a descrição do cenário."
                    logging.error("Tactical Command Orchestrator: Falha ao gerar comando pelo LLM.")

    if st.session_state.command_analysis_result:
        st.subheader("Comando Tático Gerado")
        st.markdown(st.session_state.command_analysis_result)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="command_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback Tactical Command Orchestrator: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="command_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback Tactical Command Orchestrator: Precisa de Melhoria.")

# Substitua sua função pentest_narrative_generator_page existente por esta versão completa e aprimorada.

def pentest_narrative_generator_page(llm_model_vision, llm_model_text):
    st.header("Pentest Narrative Generator 📝")
    st.markdown("""
        Gere uma narrativa de relatório de pentest abrangente e profissional. Forneça os fatos brutos
        para cada evidência, e a IA irá expandir os achados em textos ricos e contextuais, prontos para o seu relatório.
    """)
    logging.info("Página Pentest Narrative Generator (Aprimorada) acessada.")

    # --- INICIALIZAÇÃO E RESET (Lógica Mantida) ---
    # Variáveis de sessão para esta página
    if 'narrative_client_name' not in st.session_state: st.session_state.narrative_client_name = ""
    if 'narrative_app_name' not in st.session_state: st.session_state.narrative_app_name = ""
    if 'narrative_pentest_type' not in st.session_state: st.session_state.narrative_pentest_type = "Web Application"
    if 'narrative_recon_evidences' not in st.session_state: st.session_state.narrative_recon_evidences = []
    if 'narrative_vuln_evidences' not in st.session_state: st.session_state.narrative_vuln_evidences = []
    if 'narrative_resilience_evidences' not in st.session_state: st.session_state.narrative_resilience_evidences = []
    if 'generated_narrative_output' not in st.session_state: st.session_state.generated_narrative_output = ""

    def reset_narrative_generator():
        st.session_state.narrative_client_name = ""
        st.session_state.narrative_app_name = ""
        st.session_state.narrative_pentest_type = "Web Application"
        st.session_state.narrative_recon_evidences = []
        st.session_state.narrative_vuln_evidences = []
        st.session_state.narrative_resilience_evidences = []
        st.session_state.generated_narrative_output = ""
        logging.info("Pentest Narrative Generator: Campos e resultados limpos.")
        st.rerun()

    if st.button("Limpar e Gerar Nova Narrativa", key="reset_narrative_button"):
        reset_narrative_generator()

    # --- SEÇÃO 1: DETALHES DO PROJETO (Lógica Mantida) ---
    st.subheader("1. Detalhes do Projeto")
    # ... (O código para Nome do Cliente, Nome da Aplicação e Tipo de Pentest permanece o mesmo) ...
    st.session_state.narrative_client_name = st.text_input(
        "Nome do Cliente:",
        value=st.session_state.narrative_client_name,
        placeholder="Ex: Minha Empresa S.A.",
        key="narrative_client_input"
    )
    st.session_state.narrative_app_name = st.text_input(
        "Nome da Aplicação/Sistema Testado:",
        value=st.session_state.narrative_app_name,
        placeholder="Ex: Plataforma de E-commerce",
        key="narrative_app_input"
    )
    pentest_type_options = ["Web Application", "API", "Infrastructure", "Mobile"]
    st.session_state.narrative_pentest_type = st.selectbox(
        "Tipo de Pentest Principal:",
        options=pentest_type_options,
        index=pentest_type_options.index(st.session_state.narrative_pentest_type),
        key="narrative_pentest_type_select_narrative",
        help="O LLM adaptará a narrativa e o foco das vulnerabilidades com base neste tipo de pentest."
    )


    # --- SEÇÃO 2: EVIDÊNCIAS (LÓGICA ATUALIZADA) ---
    st.subheader("2. Detalhamento das Evidências por Categoria")
    st.info("Adicione suas evidências (imagens e fatos brutos). A IA usará esses dados para construir a narrativa.")

    # --- Evidências de Reconhecimento ---
    with st.expander("Evidências de Reconhecimento e Mapeamento", expanded=True):
        new_recon_files = st.file_uploader("Adicionar imagens de Reconhecimento:", type=["jpg", "jpeg", "png"], accept_multiple_files=True, key="recon_uploader")
        if new_recon_files:
            # ... (Lógica de upload de arquivos mantida, mas atualizamos os campos do dicionário) ...
            for uploaded_file in new_recon_files:
                # Simplificando para focar na lógica principal
                 st.session_state.narrative_recon_evidences.append({
                        'image': Image.open(uploaded_file), 'finding_name': '', 'raw_description': '', 'report_image_filename': uploaded_file.name,
                        'raw_tool_output': '', 'id': str(uuid.uuid4()), 'name': uploaded_file.name
                    })

        for i, ev in enumerate(st.session_state.narrative_recon_evidences):
            st.markdown(f"--- \n **Recon Evidência #{i+1}:** `{ev['name']}`")
            st.image(ev['image'], width=300)
            ev['finding_name'] = st.text_input("Nome do Achado de Reconhecimento:", value=ev.get('finding_name', ''), placeholder="Ex: Subdomínio de Desenvolvimento Exposto", key=f"recon_name_{ev['id']}")
            ev['raw_description'] = st.text_area("Descrição Bruta (Fatos):", value=ev.get('raw_description', ''), placeholder="Ex: Encontrado o subdomínio dev.empresa.com, que está publicamente acessível.", key=f"recon_desc_{ev['id']}", height=75)
            # ... (Campos para nome do arquivo e output de ferramenta mantidos) ...

    # --- Evidências de Vulnerabilidades ---
    with st.expander("Evidências de Vulnerabilidades Encontradas", expanded=True):
        new_vuln_files = st.file_uploader("Adicionar imagens de Vulnerabilidades:", type=["jpg", "jpeg", "png"], accept_multiple_files=True, key="vuln_uploader")
        if new_vuln_files:
            # ... (Lógica de upload de arquivos mantida, com novos campos) ...
             for uploaded_file in new_vuln_files:
                st.session_state.narrative_vuln_evidences.append({
                        'image': Image.open(uploaded_file), 'vulnerability_name': '', 'severity': 'Média', 'affected_endpoint': '', 'poc': '', 'context': '',
                        'report_image_filename': uploaded_file.name, 'id': str(uuid.uuid4()), 'name': uploaded_file.name
                    })

        for i, ev in enumerate(st.session_state.narrative_vuln_evidences):
            st.markdown(f"--- \n **Vulnerabilidade Evidência #{i+1}:** `{ev['name']}`")
            st.image(ev['image'], width=300)
            ev['vulnerability_name'] = st.text_input("Nome da Vulnerabilidade:", value=ev.get('vulnerability_name', ''), placeholder="Ex: SQL Injection Blind", key=f"vuln_name_{ev['id']}")
            ev['severity'] = st.selectbox("Severidade:", ["Crítica", "Alta", "Média", "Baixa", "Informativa"], index=2, key=f"vuln_sev_{ev['id']}")
            ev['affected_endpoint'] = st.text_input("Endpoint/Parâmetro Afetado:", value=ev.get('affected_endpoint', ''), placeholder="Ex: GET /api/products?id=...", key=f"vuln_endpoint_{ev['id']}")
            ev['poc'] = st.text_area("Prova de Conceito (PoC) Simples:", value=ev.get('poc', ''), placeholder="Ex: 1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -", key=f"vuln_poc_{ev['id']}", height=75)
            ev['context'] = st.text_area("Observações/Contexto Adicional:", value=ev.get('context', ''), placeholder="Ex: A aplicação não usa prepared statements.", key=f"vuln_context_{ev['id']}", height=75)
            # ... (Campo para nome do arquivo mantido) ...

    # --- Evidências de Resiliência ---
    with st.expander("Evidências de Testes de Resiliência (Pontos Fortes)", expanded=True):
        new_res_files = st.file_uploader("Adicionar imagens de Resiliência:", type=["jpg", "jpeg", "png"], accept_multiple_files=True, key="res_uploader")
        if new_res_files:
            # ... (Lógica de upload de arquivos mantida, com novos campos) ...
             for uploaded_file in new_res_files:
                st.session_state.narrative_resilience_evidences.append({
                        'image': Image.open(uploaded_file), 'control_name': '', 'positive_description': '', 'report_image_filename': uploaded_file.name,
                        'raw_tool_output': '', 'id': str(uuid.uuid4()), 'name': uploaded_file.name
                    })

        for i, ev in enumerate(st.session_state.narrative_resilience_evidences):
            st.markdown(f"--- \n **Resiliência Evidência #{i+1}:** `{ev['name']}`")
            st.image(ev['image'], width=300)
            ev['control_name'] = st.text_input("Controle de Segurança Testado:", value=ev.get('control_name', ''), placeholder="Ex: Proteção contra Clickjacking (X-Frame-Options)", key=f"res_name_{ev['id']}")
            ev['positive_description'] = st.text_area("Descrição do Resultado Positivo:", value=ev.get('positive_description', ''), placeholder="Ex: O header X-Frame-Options: SAMEORIGIN foi encontrado.", key=f"res_desc_{ev['id']}", height=75)
            # ... (Campos para nome do arquivo e output de ferramenta mantidos) ...

    # --- SEÇÃO 3: GERAÇÃO DA NARRATIVA (LÓGICA ATUALIZADA) ---
    st.subheader("3. Gerar Narrativa")
    if st.button("Gerar Narrativa de Pentest Aprimorada", key="generate_rich_narrative_button"):
        # ... (Validações de campos de projeto mantidas) ...

        with st.spinner("A IA está escrevendo as narrativas detalhadas para cada achado..."):
            
            # Textos gerados para cada seção
            recon_narratives = []
            vuln_narratives = []
            resilience_narratives = []
            conclusion_narrative = ""

            # 1. Gerar narrativas de Reconhecimento
            for ev in st.session_state.narrative_recon_evidences:
                prompt = f"""Você é um analista de inteligência de ameaças escrevendo a seção de mapeamento de superfície de ataque. Com base na evidência:
                            - Achado: {ev['finding_name']}
                            - Descrição Bruta: {ev['raw_description']}
                            Elabore um parágrafo rico para o relatório, explicando o achado, seu significado do ponto de vista de um atacante e os riscos potenciais.
                         """
                recon_narratives.append(obter_resposta_llm(llm_model_text, [prompt]))

            # 2. Gerar narrativas de Vulnerabilidades
            for ev in st.session_state.narrative_vuln_evidences:
                prompt = f"""Você é um especialista em cibersegurança e redator técnico. Com base nas informações:
                            - Nome da Vulnerabilidade: {ev['vulnerability_name']}
                            - Endpoint Afetado: {ev['affected_endpoint']}
                            - Prova de Conceito: {ev['poc']}
                            - Contexto Adicional: {ev['context']}
                            Gere uma seção detalhada para o relatório, contendo os tópicos "Descrição Técnica", "Prova de Conceito (PoC)" e "Análise de Risco e Impacto no Negócio". NÃO inclua recomendações de mitigação ou referências externas.
                         """
                vuln_narratives.append(obter_resposta_llm(llm_model_text, [prompt]))

            # 3. Gerar narrativas de Resiliência
            for ev in st.session_state.narrative_resilience_evidences:
                prompt = f"""Você é um consultor de segurança sênior redigindo a seção de pontos fortes. Com base no teste:
                            - Controle Testado: {ev['control_name']}
                            - Descrição do Resultado Positivo: {ev['positive_description']}
                            Elabore um parágrafo profissional para o relatório, descrevendo o controle, o ataque que ele previne e por que é uma boa prática de segurança.
                         """
                resilience_narratives.append(obter_resposta_llm(llm_model_text, [prompt]))

            # 4. Gerar Conclusão
            # (A lógica para gerar a conclusão pode ser mantida ou aprimorada também)
            # ...

            # 5. Montar o Relatório Final
            final_report = f"""
# Relatório de Análise de Segurança para {st.session_state.narrative_app_name}

## Introdução
(Sua introdução padrão pode ser mantida aqui...)

## 1. Achados de Reconhecimento e Mapeamento
{"\n\n---\n\n".join(recon_narratives) if recon_narratives else "Nenhum achado de reconhecimento foi detalhado."}

## 2. Vulnerabilidades Identificadas
{"\n\n---\n\n".join(vuln_narratives) if vuln_narratives else "Nenhuma vulnerabilidade foi encontrada ou detalhada."}

## 3. Pontos Fortes e Controles de Segurança Eficazes
{"\n\n---\n\n".join(resilience_narratives) if resilience_narratives else "Nenhum ponto de resiliência foi detalhado."}

## 4. Conclusão
(Sua conclusão gerada pela IA pode ser inserida aqui...)
            """
            st.session_state.generated_narrative_output = final_report.strip()

    # --- Exibição do Relatório Final (Lógica Mantida) ---
    if st.session_state.generated_narrative_output:
        st.subheader("Narrativa de Pentest Gerada:")
        st.markdown(st.session_state.generated_narrative_output)
        # ... (O código para os botões de download e feedback permanece o mesmo) ...

        col_download_md, col_download_txt = st.columns(2)
        with col_download_md:
            st.download_button(
                label="Download Narrativa (.md)",
                data=st.session_state.generated_narrative_output.encode('utf-8'),
                file_name=f"narrativa_{st.session_state.narrative_client_name.replace(' ','_')}_{st.session_state.narrative_app_name.replace(' ','_')}.md",
                mime="text/markdown",
                help="Baixe a narrativa em formato Markdown, ideal para seu relatório."
            )
        with col_download_txt:
            st.download_button(
                label="Download Narrativa (.txt)",
                data=st.session_state.generated_narrative_output.encode('utf-8'),
                file_name=f"narrativa_{st.session_state.narrative_client_name.replace(' ','_')}_{st.session_state.narrative_app_name.replace(' ','_')}.txt",
                mime="text/plain",
                help="Baixe a narrativa em formato de texto simples."
            )
        
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="narrative_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback Pentest Narrative Generator: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="narrative_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback Pentest Narrative Generator: Precisa de Melhoria.")

def parse_vulnerability_summary(text_response):
    """Extrai o resumo de vulnerabilidades da resposta do LLM."""
    summary = {
        "Total": 0,
        "Críticos": 0,
        "Altos": 0,
        "Médios": 0,
        "Baixos": 0
    }

    # Procura pela linha de resumo
    summary_line = None
    lines = text_response.split('\n')
    for line in lines:
        if line.strip().startswith("Total de Achados"):
            summary_line = line
            break

    if not summary_line:
        logging.warning("Mobile Static Analyzer: Resumo de vulnerabilidades não encontrado na resposta do LLM.")
        return summary

    # Extrair números com regex
    matches = re.findall(r'(\d+)', summary_line)
    if len(matches) >= 5:
        summary["Total"] = int(matches[0])
        summary["Críticos"] = int(matches[1])
        summary["Altos"] = int(matches[2])
        summary["Médios"] = int(matches[3])
        summary["Baixos"] = int(matches[4])

    return summary


def parse_vulnerability_details(text_response):
    """Extrai os detalhes das vulnerabilidades a partir da resposta do LLM."""
    details = []
    blocks = re.split(r'\n\s*###\s*', text_response)[1:]  # Ignora o bloco antes do primeiro ###

    for block in blocks:
        lines = block.strip().split('\n')
        if not lines:
            continue

        name = re.sub(r'\*\*Nome da Vulnerabilidade:\*\*', '', lines[0]).strip()
        category = re.sub(r'\*\*Categoria OWASP Mobile.*:\*\*', '', lines[1]).strip()
        severity = re.sub(r'\*\*Severidade/Risco:\*\*', '', lines[2]).strip()
        location = re.sub(r'\*\*Localização na Especificação:\*\*', '', lines[3]).strip()
        detail = re.sub(r'\*\*Detalhes:\*\*', '', lines[4]).strip()

        if name and category and severity and location and detail:
            details.append({
                "name": name,
                "category": category,
                "severity": severity,
                "location": location,
                "details": detail
            })

    return details


def mobile_app_static_analysis_page(llm_model_vision, llm_model_text):
    st.header("Mobile Static Analyzer 📱")
    st.markdown("""
    Realize análise estática de segurança em aplicativos Android.  
    Faça upload de um arquivo `.zip` contendo o APK descompilado (saída de ferramentas como `apktool -d` ou `jadx -d`),  
    ou cole trechos de código ou o `AndroidManifest.xml` diretamente.  

    O HuntIA irá analisar o conteúdo para identificar vulnerabilidades com base na **OWASP Mobile Top 10** e fornecer recomendações.

    ⚠️ **AVISO:** Esta é uma análise estática de *primeira linha* e não substitui uma revisão de código manual completa.
    """)
    logging.info("Página Mobile Static Analyzer acessada.")

    # Inicializar variáveis de sessão
    if 'mobile_analysis_type' not in st.session_state:
        st.session_state.mobile_analysis_type = "Upload ZIP (APK Descompilado)"
    if 'uploaded_decompiled_zip' not in st.session_state:
        st.session_state.uploaded_decompiled_zip = None
    if 'manifest_content' not in st.session_state:
        st.session_state.manifest_content = ""
    if 'code_snippet_content' not in st.session_state:
        st.session_state.code_snippet_content = ""
    if 'mobile_analysis_result' not in st.session_state:
        st.session_state.mobile_analysis_result = ""
    if 'mobile_analysis_summary' not in st.session_state:
        st.session_state.mobile_analysis_summary = None

    def reset_mobile_analysis():
        st.session_state.mobile_analysis_type = "Upload ZIP (APK Descompilado)"
        st.session_state.uploaded_decompiled_zip = None
        st.session_state.manifest_content = ""
        st.session_state.code_snippet_content = ""
        st.session_state.mobile_analysis_result = ""
        st.session_state.mobile_analysis_summary = None
        logging.info("Mobile Static Analyzer: Reset de campos.")
        st.rerun()

    if st.button("Limpar Análise Mobile", key="reset_mobile_analysis_button"):
        reset_mobile_analysis()

    # Tipo de análise
    analysis_type_options = [
        "Upload ZIP (APK Descompilado)",
        "Colar AndroidManifest.xml",
        "Colar Trecho de Código (Java/Smali/Kotlin)"
    ]
    st.session_state.mobile_analysis_type = st.radio(
        "Como deseja fornecer o conteúdo para análise?",
        options=analysis_type_options,
        key="mobile_analysis_type_radio"
    )

    analyzed_content = ""
    analysis_context = ""

    # Upload ZIP
    if st.session_state.mobile_analysis_type == "Upload ZIP (APK Descompilado)":
        uploaded_zip_file = st.file_uploader("Selecione o arquivo .zip do APK descompilado:", type=["zip"], key="mobile_zip_uploader")
        if uploaded_zip_file:
            st.session_state.uploaded_decompiled_zip = uploaded_zip_file
            with tempfile.TemporaryDirectory() as tmpdir:
                try:
                    with zipfile.ZipFile(uploaded_zip_file, 'r') as zip_ref:
                        zip_ref.extractall(tmpdir)

                    manifest_path = os.path.join(tmpdir, "AndroidManifest.xml")
                    if os.path.exists(manifest_path):
                        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                            st.session_state.manifest_content = f.read()
                        analysis_context += f"Conteúdo do AndroidManifest.xml:```xml{st.session_state.manifest_content}```"

                    code_files_content = []
                    max_code_size = 200 * 1024  # 200KB
                    current_code_size = 0
                    code_file_count = 0

                    for root, _, files in os.walk(tmpdir):
                        for file in files:
                            if file.endswith(".java") or file.endswith(".smali") or file.endswith(".kt"):
                                file_path = os.path.join(root, file)
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    if current_code_size + len(content) > max_code_size:
                                        logging.info("Mobile Static Analyzer: Limite de tamanho de código atingido.")
                                        break
                                    code_files_content.append(f"- Código de: {file}\n{content}")
                                    current_code_size += len(content)
                                    code_file_count += 1

                        if current_code_size >= max_code_size:
                            break

                    if code_files_content:
                        st.session_state.code_snippet_content = "\n\n".join(code_files_content)
                        analysis_context += f"Trechos de Código (total {code_file_count} arquivos, {current_code_size / 1024:.2f} KB):```{st.session_state.code_snippet_content}```"
                        logging.info(f"Mobile Static Analyzer: {code_file_count} arquivos de código processados.")
                    else:
                        st.info("Nenhum arquivo de código relevante encontrado no ZIP.")
                        logging.info("Mobile Static Analyzer: Nenhum arquivo de código encontrado no ZIP.")

                except Exception as e:
                    st.error(f"Erro ao processar o arquivo ZIP: {e}")
                    logging.exception(f"Mobile Static Analyzer: Erro ao processar ZIP: {e}.")
                    st.session_state.uploaded_decompiled_zip = None

            analyzed_content = analysis_context.replace('{', '{{').replace('}', '}}')

    elif st.session_state.mobile_analysis_type == "Colar AndroidManifest.xml":
        st.session_state.manifest_content = st.text_area(
            "Cole o conteúdo do AndroidManifest.xml aqui:",
            value=st.session_state.manifest_content,
            placeholder="<manifest ...><uses-permission android:name=\"android.permission.INTERNET\"/>...</manifest>",
            height=400,
            key="manifest_input_area"
        )
        escaped_manifest = st.session_state.manifest_content.replace('{', '{{').replace('}', '}}')
        analyzed_content = f"Conteúdo do AndroidManifest.xml:```xml{escaped_manifest}```"
        logging.info("Mobile Static Analyzer: Conteúdo do AndroidManifest.xml lido.")

    elif st.session_state.mobile_analysis_type == "Colar Trecho de Código (Java/Smali/Kotlin)":
        st.session_state.code_snippet_content = st.text_area(
            "Cole trechos de código Java/Smali/Kotlin aqui (mantenha relevante e conciso):",
            value=st.session_state.code_snippet_content,
            placeholder="Ex: public class SecretHolder {\nprivate static final String API_KEY = \"sk-123xyz\";\n}",
            height=400,
            key="code_snippet_input_area"
        )
        escaped_code = st.session_state.code_snippet_content.replace('{', '{{').replace('}', '}}')
        analyzed_content = f"Trecho de Código para Análise:```java{escaped_code}```"
        logging.info("Mobile Static Analyzer: Trecho de código colado pelo usuário.")

    if st.button("Analisar Aplicativo Mobile", key="analyze_mobile_app_button"):
        if not analyzed_content.strip():
            st.error("Por favor, forneça o conteúdo para análise.")
            logging.warning("Mobile Static Analyzer: Análise abortada, conteúdo vazio.")
            return

        with st.spinner("Analisando aplicativo mobile estaticamente com LLM..."):
            logging.info("Mobile Static Analyzer: Iniciando análise estática.")

            global_context_prompt = get_global_context_prompt()

            mobile_analysis_prompt = (
                f"Você é um especialista em segurança de aplicativos móveis e pentest, com profundo conhecimento na **OWASP Mobile Top 10 (2024)**.\n"
                f"{global_context_prompt}\n\n"
                f"Sua tarefa é analisar o conteúdo descompilado de um aplicativo Android (APK) fornecido a seguir. Identifique **TODAS as potenciais vulnerabilidades de segurança** com base nas categorias da OWASP Mobile Top 10, bem como outras falhas comuns em aplicativos mobile.\n\n"
                f"**RESUMO:** Forneça um resumo quantitativo na PRIMEIRA LINHA da sua resposta, no formato exato: `Total de Achados: X | Críticos: Y | Altos: Z | Médios: W | Baixos: V` (substitua X,Y,Z,W,V pelos números correspondentes). Se não houver achados, use 0.\n\n"
                f"Para cada **achado de segurança** identificado, apresente de forma concisa e prática, utilizando Markdown para formatação:\n\n"
                f"### [Nome da Vulnerabilidade] (Ex: Chave de API Hardcoded, Comunicação Não Criptografada)\n"
                f"**Categoria OWASP Mobile (2024):** [Ex: M1: Improper Platform Usage]\n"
                f"**Severidade/Risco:** [Alta/Média/Baixa - explique o impacto específico para esta vulnerabilidade]\n"
                f"**Localização na Especificação:** Indique onde foi encontrada a vulnerabilidade (ex: `AndroidManifest.xml`, `MainActivity.java`).\n"
                f"**Detalhes:** Explique o problema técnico e como ele ocorre.\n\n"
                f"**Conteúdo para Análise:**\n{analyzed_content}\n\n"
                f"Se não encontrar vulnerabilidades óbvias, indique isso claramente."
            )

            analysis_result_raw = obter_resposta_llm(llm_model_text, [mobile_analysis_prompt])
            if analysis_result_raw:
                st.session_state.mobile_analysis_result = analysis_result_raw
                st.session_state.mobile_analysis_summary = parse_vulnerability_summary(analysis_result_raw)
                logging.info("Mobile Static Analyzer: Análise concluída com sucesso.")
            else:
                st.session_state.mobile_analysis_result = "Não foi possível realizar a análise estática mobile. Tente refinar o conteúdo ou ajustar o APK descompilado."
                st.session_state.mobile_analysis_summary = None
                logging.error("Mobile Static Analyzer: Falha na análise pelo LLM.")

    # Exibir resultados
    if st.session_state.mobile_analysis_result:
        st.subheader("Resultados da Análise Estática Mobile")

        if st.session_state.mobile_analysis_summary:
            cols = st.columns(5)
            cols[0].metric("Total", st.session_state.mobile_analysis_summary.get("Total", 0))
            cols[1].metric("Críticos", st.session_state.mobile_analysis_summary.get("Críticos", 0))
            cols[2].metric("Altos", st.session_state.mobile_analysis_summary.get("Altos", 0))
            cols[3].metric("Médios", st.session_state.mobile_analysis_summary.get("Médios", 0))
            cols[4].metric("Baixos", st.session_state.mobile_analysis_summary.get("Baixos", 0))

        vulnerability_details = parse_vulnerability_details(st.session_state.mobile_analysis_result)

        if vulnerability_details:
            for vuln in vulnerability_details:
                st.markdown(f"### {vuln['name']}")
                st.markdown(f"**Categoria OWASP Mobile (2024):** {vuln['category']}")
                st.markdown(f"**Severidade/Risco:** {vuln['severity']}")
                st.markdown(f"**Localização na Especificação:** {vuln['location']}")
                st.markdown(f"**Detalhes:** {vuln['details']}")
                st.markdown("---")
        else:
            st.info("Nenhuma vulnerabilidade detalhada encontrada na resposta do LLM.")

        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="mobile_analysis_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback Mobile Static Analyzer: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="mobile_analysis_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback Mobile Static Analyzer: Precisa de Melhoria.")


# --- Main Application Logic ---
def main():
    llm_model_vision, llm_model_text = get_gemini_models_cached()

    if not llm_model_vision or not llm_model_text:
        st.warning("Modelos LLM não carregados. Algumas funcionalidades podem não estar disponíveis.")
        return

    # Inicializa estados globais
    if 'global_profile' not in st.session_state: st.session_state.global_profile = "Nenhum"
    if 'global_scenario' not in st.session_state: st.session_state.global_scenario = "Nenhum"
    if 'projeto_ativo_id' not in st.session_state: st.session_state.projeto_ativo_id = None
    if 'projeto_ativo_nome' not in st.session_state: st.session_state.projeto_ativo_nome = None
    if 'modo_rascunho' not in st.session_state: st.session_state.modo_rascunho = True
    
    with st.sidebar:
        # Lógica do expander para a navegação
        with st.expander("Navegação Principal", expanded=True):
            selected = option_menu(
                menu_title=None,
                options=[
                    "Início",
                    "Configurações",
                    "Pentest Copilot", # <-- NOVO MÓDULO CONSOLIDADO
                    "Correlation Dashboard",
                    "OWASP Vulnerability Details",
                    "Deep HTTP Insight",
                    "OWASP Image Analyzer",
                    "OpenAPI Analyzer",
                    "Static Code Analyzer",
                    "Pentest Narrative Generator",
                    "Mobile Static Analyzer"
                ],
                icons=[
                    "house", "gear-fill", "robot", # <-- NOVO ÍCONE
                    "diagram-3", "bug", "globe", "image", "file-earmark-richtext", 
                    "code-slash", "check-square", "file-earmark-text", "phone"
                ],
                menu_icon="tools",
                default_index=0,
                 styles={
                    "container": {"padding": "0!important", "background-color": "#262730"},
                    "icon": {"color": "#E50000", "font-size": "20px"},
                    "nav-link": {"font-size": "16px", "text-align": "left", "margin":"0px", "--hover-color": "#4a4a5c"},
                    "nav-link-selected": {"background-color": "#E50000"},
                }
            )
        
        st.sidebar.markdown("---")
        st.sidebar.download_button(
            label="Download Log do Aplicativo",
            data=get_log_file_content(),
            file_name="huntia_application.log",
            mime="text/plain"
        )

    # Lógica de roteamento para cada página da aplicação
    if selected == "Início":
        home_page()
    elif selected == "Configurações":
        settings_page()
    elif selected == "Pentest Copilot":
        pentest_copilot_page(llm_model_text) # <-- ROTA PARA A NOVA PÁGINA
    elif selected == "Correlation Dashboard":
        correlation_dashboard_page(llm_model_text)
    elif selected == "OWASP Vulnerability Details":
        owasp_text_analysis_page(llm_model_vision, llm_model_text)
    elif selected == "Deep HTTP Insight":
        http_request_analysis_page(llm_model_vision, llm_model_text)
    elif selected == "OWASP Image Analyzer":
        owasp_scout_visual_page(llm_model_vision, llm_model_text)
    elif selected == "Advanced OpenAPI Analzyer":
        advanced_openapi_analyzer_page(llm_model_vision, llm_model_text)
    elif selected == "Static Code Analyzer":
        static_code_analyzer_page(llm_model_text)
    elif selected == "Pentest Narrative Generator":
        pentest_narrative_generator_page(llm_model_vision, llm_model_text)
    elif selected == "Mobile Static Analyzer":
        mobile_app_static_analysis_page(llm_model_vision, llm_model_text)

if __name__ == "__main__":
    main()
