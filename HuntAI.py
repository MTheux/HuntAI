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

def poc_generator_html_page(llm_model_vision, llm_model_text):
    st.header("PoC Generator (HTML): Crie Provas de Conceito em HTML 📄")
    st.markdown("""
        Gere códigos HTML de Prova de Conceito para testar vulnerabilidades específicas no navegador.
        Perfeito para demonstrar falhas como CSRF, Clickjacking, CORS, e XSS baseados em HTML.
    """)
    logging.info("Página PoC Generator (HTML) acessada.")

    # --- Início do Bloco Universal de Verificação ---
    if not st.session_state.get('projeto_ativo_id') and not st.session_state.get('modo_rascunho'):
        st.error("Por favor, selecione um projeto ou ative o 'Modo Rascunho' na página de Configurações.")
        st.stop()
    
    if st.session_state.get('modo_rascunho'):
        st.info("Você está no Modo Rascunho. Esta PoC não será salva. ✏️")
    else:
        st.success(f"Gerando PoC para o projeto: **{st.session_state.projeto_ativo_nome}**")
    st.markdown("---")
    # --- Fim do Bloco Universal ---

    # Initialize session state variables for this page
    if 'poc_gen_vulnerability_input' not in st.session_state:
        st.session_state.poc_gen_vulnerability_input = ""
    if 'poc_gen_context_input' not in st.session_state:
        st.session_state.poc_gen_context_input = ""
    if 'poc_gen_html_output' not in st.session_state:
        st.session_state.poc_gen_html_output = ""
    if 'poc_gen_instructions' not in st.session_state:
        st.session_state.poc_gen_instructions = ""
    if 'poc_gen_payload_example' not in st.session_state:
        st.session_state.poc_gen_payload_example = ""

    def reset_poc_generator():
        st.session_state.poc_gen_vulnerability_input = ""
        st.session_state.poc_gen_context_input = ""
        st.session_state.poc_gen_html_output = ""
        st.session_state.poc_gen_instructions = ""
        st.session_state.poc_gen_payload_example = ""
        logging.info("PoC Generator (HTML): Reset de campos.")
        st.rerun()

    if st.button("Limpar Gerador", key="reset_poc_gen_button"):
        reset_poc_generator()

    vulnerability_input = st.text_input(
        "Digite a vulnerabilidade para gerar a PoC HTML (Ex: CSRF, Clickjacking, CORS, XSS):",
        value=st.session_state.poc_gen_vulnerability_input,
        placeholder="Ex: CSRF, Clickjacking, CORS, XSS refletido",
        key="poc_gen_vuln_input"
    )
    st.session_state.poc_gen_vulnerability_input = vulnerability_input.strip()

    context_input = st.text_area(
        "Contexto Adicional (URL alvo, parâmetros, método, etc.):",
        value=st.session_state.poc_gen_context_input,
        placeholder="Ex: 'URL: https://exemplo.com/transferencia, Parâmetros: conta=123&valor=100, Método: POST'",
        height=150,
        key="poc_gen_context_input_area"
    )
    st.session_state.poc_gen_context_input = context_input.strip()

    if st.button("Gerar PoC HTML", key="generate_poc_html_button"):
        if not st.session_state.poc_gen_vulnerability_input:
            st.error("Por favor, digite a vulnerabilidade para gerar a PoC.")
            logging.warning("PoC Generator (HTML): Geração abortada, vulnerabilidade vazia.")
            return
        else:
            with st.spinner(f"Gerando PoC HTML para {st.session_state.poc_gen_vulnerability_input}..."):
                logging.info(f"PoC Generator (HTML): Gerando PoC para {st.session_state.poc_gen_vulnerability_input}.")

                # Injetando Contexto e Verbosidade
                global_context_prompt = get_global_context_prompt()
                verbosity_prompt = get_verbosity_prompt()

                poc_prompt = (
                    f"Você é um especialista em pentest e possui autorização para realizar testes de segurança. "
                    f"{global_context_prompt}"
                    f"\n\n{verbosity_prompt}\n\n"
                    f"Sua tarefa é gerar uma Prova de Conceito (PoC) em HTML funcional e um payload/instruções para demonstrar a vulnerabilidade '{st.session_state.poc_gen_vulnerability_input}'.\n"
                    f"**Contexto:** {st.session_state.poc_gen_context_input if st.session_state.poc_gen_context_input else 'Nenhum contexto adicional fornecido.'}\n\n"
                    f"Forneça as informações nos seguintes tópicos:\n\n"
                    f"## 1. Detalhes da Vulnerabilidade e Como Funciona\n"
                    f"Uma breve explicação do que é a vulnerabilidade, como ela funciona e como a PoC a demonstra, respeitando o nível de verbosidade solicitado.\n\n"
                    f"## 2. Código HTML da PoC (Completo e Mínimo)\n"
                    f"Forneça um **código HTML COMPLETO e MÍNIMO** (com tags `<html>`, `<head>`, `<body>`) que simule um cenário vulnerável a **{st.session_state.poc_gen_vulnerability_input}**.\n"
                    f"Este HTML deve ser funcional e auto-contido. O foco é na vulnerabilidade, não no design.\n"
                    f"Encapsule o HTML completo em um bloco de código Markdown com a linguagem `html` (` ```html).\n\n"
                    f"## 3. Instruções de Uso e Payload (se aplicável)\n"
                    f"Descreva como o usuário deve usar este HTML para testar a PoC. Se for necessário um payload ou comando específico (ex: um script XSS, uma URL modificada para Clickjacking), forneça-o explicitamente e encapsule-o em um bloco de código Markdown com la linguagem apropriada (ex: ` ```js `, ` ```sql `, ` ```bash `).\n"
                    f"\nSeja direto, prático e didático. O objetivo é que o usuário (um pentester autorizado) possa copiar e colar o HTML e as instruções para testar a falha em um ambiente de teste autorizado."
                )

                poc_generation_raw = obter_resposta_llm(llm_model_text, [poc_prompt])

                if poc_generation_raw:
                    st.session_state.poc_gen_instructions = poc_generation_raw

                    # Sua lógica de parsing original (mantida)
                    html_start = poc_generation_raw.find("```html")
                    html_end = poc_generation_raw.find("```", html_start + len("```html"))
                    payload_start_marker = "```"
                    if html_start != -1 and html_end != -1:
                        payload_start = poc_generation_raw.find(payload_start_marker, html_end + 1)
                    else:
                        payload_start = poc_generation_raw.find(payload_start_marker)
                    payload_end = -1
                    if payload_start != -1:
                        payload_end = poc_generation_raw.find(payload_start_marker, payload_start + len(payload_start_marker))
                        if payload_end == payload_start:
                            payload_end = -1
                    if html_start != -1 and html_end != -1:
                        st.session_state.poc_gen_html_output = poc_generation_raw[html_start + len("```html") : html_end].strip()
                    else:
                        st.session_state.poc_gen_html_output = "Não foi possível extrair o HTML do PoC. Verifique a resposta do LLM."
                        logging.warning("PoC Generator (HTML): HTML não extraído da resposta do LLM.")
                    if payload_start != -1 and payload_end != -1:
                        payload_content = poc_generation_raw[payload_start + len(payload_start_marker) : payload_end].strip()
                        if '\n' in payload_content and payload_content.splitlines()[0].strip().isalpha():
                            st.session_state.poc_gen_payload_example = '\n'.join(payload_content.splitlines()[1:])
                        else:
                            st.session_state.poc_gen_payload_example = payload_content
                        logging.info("PoC Generator (HTML): PoC gerado com sucesso.")
                    else:
                        st.session_state.poc_gen_payload_example = "Não foi possível extrair o exemplo de payload. Verifique a resposta do LLM."
                        logging.warning("PoC Generator (HTML): Payload não extraído da resposta do LLM.")

                    # Início do Padrão Universal de Salvamento
                    if not st.session_state.get('modo_rascunho', False):
                        try:
                            resumo_para_db = f"PoC HTML Gerada para: '{st.session_state.poc_gen_vulnerability_input}' com contexto: '{st.session_state.poc_gen_context_input}'"
                            database.salvar_analise(
                                projeto_id=st.session_state.projeto_ativo_id,
                                tipo_analise="PoC Generator (HTML)",
                                resumo_input=resumo_para_db,
                                resultado_completo=poc_generation_raw
                            )
                            st.toast("PoC HTML salva com sucesso no projeto!", icon="💾")
                        except Exception as e:
                            st.error(f"Houve um erro ao salvar a PoC no banco de dados: {e}")
                    else:
                        st.toast("Modo Rascunho: Resultado não salvo.", icon="✏️")
                    # Fim do Padrão Universal de Salvamento
                else:
                    st.session_state.poc_gen_instructions = "Não foi possível gerar a PoC HTML para a vulnerabilidade selecionada."
                    st.session_state.poc_gen_html_output = ""
                    st.session_state.poc_gen_payload_example = ""
                    logging.error("PoC Generator (HTML): Falha na geração da PoC pelo LLM.")

    if st.session_state.poc_gen_html_output or st.session_state.poc_gen_instructions:
        st.subheader("Results da PoC HTML")

        st.markdown(st.session_state.poc_gen_instructions)

        if st.session_state.poc_gen_html_output:
            st.markdown("#### Mini-Laboratório HTML (Copie e Cole em um arquivo .html e abra no navegador)")
            st.code(st.session_state.poc_gen_html_output, language="html")

            st.markdown("---")
            st.markdown("#### Teste o Laboratório Aqui (Visualização Direta)")
            st.warning("AVISO: Esta visualização direta é para conveniência. Para um teste real e isolado, **salve o HTML em um arquivo .html e abra-o diretamente no seu navegador**.")
            components.html(st.session_state.poc_gen_html_output, height=300, scrolling=True)
            st.markdown("---")

        if st.session_state.poc_gen_payload_example:
            st.markdown("#### Exemplo de Payload/Comando para Teste")
            payload_lang = "plaintext"
            first_line = st.session_state.poc_gen_payload_example.splitlines()[0].strip() if st.session_state.poc_gen_payload_example else ""

            if "alert(" in st.session_state.poc_gen_payload_example.lower() or "document.write" in st.session_state.poc_gen_payload_example.lower():
                payload_lang = "js"
            elif "SELECT " in st.session_state.poc_gen_payload_example.upper() and "FROM " in st.session_state.poc_gen_payload_example.upper():
                payload_lang = "sql"
            elif "http" in first_line.lower() and ("post" in first_line.lower() or "get" in first_line.lower()):
                payload_lang = "http"
            elif "curl " in first_line.lower() or "bash" in first_line.lower():
                payload_lang = "bash"
            elif "python" in first_line.lower() or "import" in st.session_state.poc_gen_payload_example.lower():
                payload_lang = "python"

            st.code(st.session_state.poc_gen_payload_example, language=payload_lang)
        
        # Feedback Buttons (mantidos)
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="poc_gen_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback PoC Generator (HTML): Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="poc_gen_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback PoC Generator (HTML): Precisa de Melhoria.")

def static_code_analyzer_page(llm_model_vision, llm_model_text):
    st.header("Static Code Analyzer (Avançado para JS/RAW) 👨‍💻")
    st.markdown("""
        Cole um trecho de código ou o RAW de uma resposta HTTP contendo JavaScript.
        O HuntIA irá identificar **vulnerabilidades (OWASP Top 10), padrões de exposição de informações sensíveis (chaves, IPs, tokens, credenciais hardcoded)** e sugerir correções e Provas de Conceito.
        **Especialmente otimizado para análise de arquivos JavaScript e conteúdo HTTP RAW.**
        **AVISO:** Esta é uma análise de *primeira linha* e não substitui um SAST completo.
    """)
    logging.info("Página Static Code Analyzer acessada.")

    if 'code_input_content' not in st.session_state:
        st.session_state.code_input_content = ""
    if 'code_analysis_result' not in st.session_state:
        st.session_state.code_analysis_result = ""
    if 'code_language_selected' not in st.session_state:
        st.session_state.code_language_selected = "JavaScript" # Padrão para JS
    if 'input_type_selected' not in st.session_state:
        st.session_state.input_type_selected = "Código JavaScript Direto" # Novo estado para tipo de input

    def reset_code_analyzer():
        st.session_state.code_input_content = ""
        st.session_state.code_analysis_result = ""
        st.session_state.code_language_selected = "JavaScript"
        st.session_state.input_type_selected = "Código JavaScript Direto"
        logging.info("Static Code Analyzer: Reset de campos.")
        st.rerun()

    if st.button("Limpar Análise de Código", key="reset_code_analysis_button"):
        reset_code_analyzer()

    input_type = st.radio(
        "Tipo de Conteúdo para Análise:",
        ("Código JavaScript Direto", "HTTP RAW (Corpo JavaScript)"),
        key="static_code_input_type_radio",
        index=0 if st.session_state.input_type_selected == "Código JavaScript Direto" else 1
    )
    st.session_state.input_type_selected = input_type

    code_placeholder = "Cole seu código JavaScript aqui. Ex: const apiKey = 'sk-xxxxxxxxxxxxx';\nfetch('/api/data', { headers: { Authorization: token } });"
    if input_type == "HTTP RAW (Corpo JavaScript)":
        code_placeholder = "Cole a requisição/resposta HTTP RAW que contenha JavaScript no corpo (ex: resposta de um arquivo .js).\nEx: HTTP/1.1 200 OK\nContent-Type: application/javascript\n...\n\nconst secretKey = 'mySuperSecret';"

    code_content = st.text_area(
        "Cole o conteúdo para análise aqui:",
        value=st.session_state.code_input_content,
        placeholder=code_placeholder,
        height=400,
        key="code_input_area"
    )
    st.session_state.code_input_content = code_content.strip()

    # Se o tipo de input for HTTP RAW, tentamos extrair o corpo
    analyzed_content = ""
    effective_language = st.session_state.code_language_selected # Manter para o prompt

    if input_type == "HTTP RAW (Corpo JavaScript)":
        parsed_http = parse_raw_http_request(st.session_state.code_input_content)
        analyzed_content = parsed_http['body']
        if not analyzed_content:
            st.warning("Nenhum corpo de requisição/resposta HTTP RAW com JavaScript detectado. Certifique-se de que o JavaScript esteja no corpo e não apenas em headers.")
            logging.warning("Static Code Analyzer: Nenhum corpo HTTP RAW detectado para análise JS.")
            # Continuar com o conteúdo bruto se não encontrar corpo, para o LLM tentar de alguma forma
            analyzed_content = st.session_state.code_input_content
        else:
            st.info("Corpo JavaScript extraído do HTTP RAW para análise.")
            logging.info("Static Code Analyzer: Corpo JS extraído de HTTP RAW.")
        effective_language = "JavaScript" # Forçar JavaScript para análise de RAW
    else:
        analyzed_content = st.session_state.code_input_content
        # Para "Código JavaScript Direto", o usuário pode ainda querer especificar a linguagem, mas JS é o foco
        language_options = ["JavaScript", "Python", "Java", "PHP", "Go", "Ruby", "C#", "SQL", "Outra"]
        selected_language = st.selectbox(
            "Linguagem do Código (se não for JavaScript):",
            options=language_options,
            index=language_options.index(st.session_state.code_language_selected),
            key="code_language_select"
        )
        st.session_state.code_language_selected = selected_language
        effective_language = selected_language

    if st.button("Analisar Código/Conteúdo", key="analyze_code_button"):
        if not analyzed_content:
            st.error("Por favor, cole o conteúdo para análise.")
            logging.warning("Static Code Analyzer: Análise abortada, conteúdo vazio.")
            return
        
        with st.spinner(f"Analisando código/conteúdo ({effective_language}) com LLM..."):
            logging.info(f"Static Code Analyzer: Iniciando análise de código/conteúdo (tipo: {input_type}, linguagem efetiva: {effective_language}).")

            # --- INJETANDO O CONTEXTO GLOBAL ---
            global_context_prompt = get_global_context_prompt()
            # --- FIM INJEÇÃO DE CONTEXTO ---

            code_prompt = (
                f"Você é um especialista em segurança de código e pentest, com foco em análise estática de código e detecção de segredos. "
                f"{global_context_prompt}" # INJETANDO CONTEXTO GLOBAL
                f"\n\nAnalise o seguinte trecho de código/conteúdo na linguagem {effective_language}. "
                f"Seu objetivo é ser EXTREMAMENTE CERTEIRO e identificar **TODAS as potenciais vulnerabilidades de segurança (baseadas na OWASP Top 10 e outras falhas comuns)** e, crucialmente, **exposição de informações sensíveis e segredos**, tais como:\n"
                f"- **Chaves de API, tokens de autenticação, chaves secretas (API_KEY, secret_key, token, bearer, password, access_token, refresh_token, client_secret, etc.)**\n"
                f"- **Credenciais hardcoded (usuários e senhas)**\n"
                f"- Endereços IP de servidores, domínios internos/de desenvolvimento (ex: `192.168.1.1`, `dev.api.internal`, `test.database.com`)\n"
                f"- URLs internas, endpoints de admin ou de debug expostos (ex: `/admin/`, `/debug`, `/.git/`)\n"
                f"- Comentários de desenvolvedores que possam conter informações sensíveis (ex: `TODO: remover esta senha`, `FIXME: credenciais hardcoded aqui`, `username: admin / password: 123`)\n"
                f"- Nomes de diretórios ou caminhos de arquivos internos/sensíveis (ex: `/var/www/backup`, `/admin/dev_tools`, `C:\\secrets\\config.ini`)\n"
                f"- **String de conexão de banco de dados, chaves de criptografia, valores salt, etc.**\n\n"
                f"**Priorize a busca por API keys, tokens e credenciais expostas, especialmente em código JavaScript, que é o foco primário aqui.**"
                f"\n\n**Conteúdo para análise:**\n```\n{analyzed_content}\n```\n\n"
                f"Para cada **achado (vulnerabilidade ou informação sensível)** identificado, apresente de forma concisa e prática, utilizando Markdown:\n\n"
                f"## [Tipo de Achado (Ex: Chave de API Exposta, Credenciais Hardcoded, Injeção XSS em JS)]\n"
                f"**Categoria OWASP (se aplicável):** [Ex: A02: Cryptographic Failures, A05: Security Misconfiguration, A03: Injection]. Se for uma informação sensível não OWASP, indique 'Exposição de Informação Sensível'.\n"
                f"**Severidade/Risco:** [Crítica/Alta/Média/Baixa - explique o impacto direto e o risco real deste achado específico, tanto para vulnerabilidades quanto para informações expostas. Seja preciso no impacto.]\n"
                f"**Localização no Conteúdo:** Explique onde no conteúdo a falha/informação foi observada. Inclua o **número da linha aproximado** se possível. Ex: `Linha 5: A variável 'apiKey' contém um segredo hardcoded.`\n"
                f"**Trecho de Código/Conteúdo Afetado:** Forneça o trecho de código exato que contém a falha ou informação sensível. Encapsule-o em um bloco de código Markdown com a linguagem correspondente (ex: ```javascript, ```python). Este trecho deve ser facilmente identificável no conteúdo original.\n\n"
                f"**Exemplo de PoC/Cenário de Exploração (se aplicável):** Descreva os passos para explorar a vulnerabilidade ou o risco de exposição da informação. Forneça exemplos de payloads, comandos ou trechos de código que demonstrem o problema. Para informações sensíveis, explique como essa exposição pode ser explorada (ex: acesso a sistemas, reconhecimento, pivotagem, uso indevido da API exposta).\n"
                f"Encapsule os exemplos de código em blocos de código Markdown (` ```{effective_language} ` ou ` ```bash ` ou ` ```http `).\n\n"
                f"**Ferramentas Sugeridas (se aplicável):** Liste ferramentas que podem ser usadas para explorar ou validar este achado. (Ex: `grep` para buscas de strings, `curl` para testar URLs, Burp Suite para replay/modificação, `JSScanner`, `gitleaks` para repositórios).\n\n"
                f"**Recomendação/Mitigação:** Ações concretas, detalhadas e específicas para corrigir o problema ou mitigar o risco (ex: mover secrets para variáveis de ambiente/cofre, usar autenticação baseada em tokens temporários, sanitizar input, configurar permissões adequadas, remover diretórios desnecessários).\n\n"
                f"Se não encontrar vulnerabilidades óbvias ou informações sensíveis, indique isso claramente. Lembre-se, sua análise é uma *primeira linha* e não substitui um SAST completo ou uma revisão de código manual profunda.\n\n"
            )

            code_analysis_raw = obter_resposta_llm(llm_model_text, [code_prompt])

            if code_analysis_raw:
                st.session_state.code_analysis_result = code_analysis_raw
                logging.info("Static Code Analyzer: Análise de código/conteúdo concluída com sucesso.")
            else:
                st.session_state.code_analysis_result = "Não foi possível obter a análise de código. Tente novamente."
                logging.error("Static Code Analyzer: Falha na obtenção da análise de código/conteúdo do LLM.")

    if st.session_state.code_analysis_result:
        st.subheader("Results da Análise de Código/Conteúdo")
        st.markdown(st.session_state.code_analysis_result)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="static_code_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback Static Code Analyzer: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="static_code_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback Static Code Analyzer: Precisa de Melhoria.")


def swagger_openapi_analyzer_page(llm_model_vision, llm_model_text):
    st.header("OpenAPI Analyzer: Análise de APIs (Swagger/OpenAPI) 📄")
    st.markdown("""
    Cole o conteúdo de um arquivo OpenAPI (JSON ou YAML) para analisar a especificação da API em busca de:
    - **Vulnerabilidades OWASP API Security Top 10 (2023)**
    - Falhas de design e implementação
    - Exposição de informações sensíveis
    - Boas práticas de segurança e sugestões de melhoria
    """)

    logging.info("Página OpenAPI Analyzer acessada.")

    # Inicializar variáveis de sessão
    if 'swagger_input_content' not in st.session_state:
        st.session_state.swagger_input_content = ""
    if 'swagger_analysis_result_display' not in st.session_state:
        st.session_state.swagger_analysis_result_display = ""
    if 'swagger_context_input' not in st.session_state:
        st.session_state.swagger_context_input = ""
    if 'swagger_summary' not in st.session_state:
        st.session_state.swagger_summary = None

    def reset_swagger_analyzer():
        st.session_state.swagger_input_content = ""
        st.session_state.swagger_analysis_result_display = ""
        st.session_state.swagger_context_input = ""
        st.session_state.swagger_summary = None
        logging.info("OpenAPI Analyzer: Reset de campos.")
        st.rerun()

    if st.button("Limpar Análise OpenAPI", key="reset_swagger_analysis_button"):
        reset_swagger_analyzer()

    # Entrada de conteúdo OpenAPI
    st.session_state.swagger_input_content = st.text_area(
        "Cole o conteúdo do arquivo OpenAPI (JSON ou YAML) aqui:",
        value=st.session_state.swagger_input_content,
        placeholder="Ex: { 'openapi': '3.0.0', 'info': { ... }, 'paths': { ... } }",
        height=400,
        key="swagger_input_area"
    )

    # Contexto adicional opcional
    st.session_state.swagger_context_input = st.text_area(
        "Contexto Adicional (opcional):",
        value=st.session_state.swagger_context_input,
        placeholder="Ex: 'Esta API é para gerenciamento de usuários', 'É uma API interna para microserviços'",
        height=150,
        key="swagger_context_input_area"
    )

    if st.button("Analisar OpenAPI", key="analyze_swagger_button"):
        if not st.session_state.swagger_input_content.strip():
            st.error("Por favor, cole o conteúdo OpenAPI/Swagger para análise.")
            logging.warning("OpenAPI Analyzer: Análise abortada, conteúdo vazio.")
            return

        with st.spinner("Analisando especificação OpenAPI/Swagger..."):
            logging.info("OpenAPI Analyzer: Iniciando análise de especificação.")

            # Detectar formato do conteúdo
            content_format = "TEXTO SIMPLES (formato inválido, análise pode ser limitada)"
            code_lang = "plaintext"
            try:
                json.loads(st.session_state.swagger_input_content)
                content_format = "JSON"
                code_lang = "json"
            except json.JSONDecodeError:
                try:
                    yaml.safe_load(st.session_state.swagger_input_content)
                    content_format = "YAML"
                    code_lang = "yaml"
                except yaml.YAMLError:
                    st.warning("O conteúdo colado não parece ser um JSON ou YAML válido. A análise pode ser limitada.")
                    logging.warning("OpenAPI Analyzer: Conteúdo não é JSON ou YAML válido.")

            # Prompt para o LLM
            global_context_prompt = get_global_context_prompt()
            swagger_prompt = (
                f"Você é um especialista em segurança de APIs e pentest, com profundo conhecimento na OWASP API Security Top 10 (2023). "
                f"{global_context_prompt} \n\n"
                f"Sua tarefa é analisar a especificação OpenAPI (Swagger) fornecida ({content_format}) e o contexto adicional: '{st.session_state.swagger_context_input}', identificando **TODAS as possíveis vulnerabilidades de segurança e falhas de design**.\n\n"
                f"Para cada vulnerabilidade/falha identificada, forneça os seguintes tópicos de forma separada e concisa, utilizando Markdown. **Comece cada achado com um cabeçalho `###`:**\n\n"
                f"### [Nome da Vulnerabilidade/Falha de Design]\n"
                f"**Categoria OWASP API Security Top 10 (2023):** [Ex: API1: Broken Object Level Authorization (BOLA), API8: Security Misconfiguration]. Se não se encaixa diretamente, use 'Falha de Design Geral'.\n"
                f"**Severidade/Risco:** [Crítica/Alta/Média/Baixa - explique o impacto específico para esta API]\n"
                f"**Localização na Especificação:** Indique o caminho exato ou uma descrição clara de onde a falha foi observada na especificação OpenAPI (ex: `/paths/{{userId}}/details GET`, `components/schemas/UserObject`).\n"
                f"**Exemplo de Exploração:** Descreva como um atacante poderia explorar a vulnerabilidade. Forneça um comando simples, um payload ou uma explicação de como testar/explorar.\n"
                f"**Recomendação/Mitigação:** Ações concretas e específicas para corrigir a vulnerabilidade ou melhorar o design da API, relevantes para a especificação OpenAPI fornecida.\n"
                f"\n"
                f"**Conteúdo da Especificação OpenAPI/Swagger (para sua referência):**\n"
                f"```{code_lang}\n{st.session_state.swagger_input_content}\n```\n\n"
                f"Se não encontrar vulnerabilidades óbvias, indique isso claramente e sugira melhorias gerais de segurança."
            )

            # Obter resposta do LLM
            analysis_raw = obter_resposta_llm(llm_model_text, [swagger_prompt])
            if analysis_raw:
                st.session_state.swagger_analysis_result_display = analysis_raw

                # Extrair resumo
                summary_match = re.search(
                    r'Total de Vulnerabilidades API:\s*(\d+)\s*\|\s*Críticas:\s*(\d+)\s*\|\s*Altas:\s*(\d+)\s*\|\s*Médios:\s*(\d+)\s*\|\s*Baixos:\s*(\d+)',
                    analysis_raw
                )
                if summary_match:
                    total, criticos, altos, medios, baixos = map(int, summary_match.groups())
                    st.session_state.swagger_summary = {
                        "Total": total,
                        "Críticas": criticos,
                        "Altas": altos,
                        "Médios": medios,
                        "Baixos": baixos
                    }
                else:
                    st.session_state.swagger_summary = {"Total": 0, "Críticas": 0, "Altas": 0, "Médios": 0, "Baixos": 0}
                    logging.warning("OpenAPI Analyzer: Resumo de vulnerabilidades não encontrado na resposta do LLM.")
            else:
                st.session_state.swagger_analysis_result_display = "Não foi possível obter a análise da especificação OpenAPI. Tente novamente."
                st.session_state.swagger_summary = None
                logging.error("OpenAPI Analyzer: Falha na obtenção da análise do LLM.")

    # Exibir resultados
    if st.session_state.swagger_analysis_result_display:
        st.subheader("Resultados da Análise OpenAPI")

        if st.session_state.swagger_summary:
            cols = st.columns(5)
            cols[0].metric("Total", st.session_state.swagger_summary.get("Total", 0))
            cols[1].metric("Críticas", st.session_state.swagger_summary.get("Críticas", 0))
            cols[2].metric("Altas", st.session_state.swagger_summary.get("Altas", 0))
            cols[3].metric("Médios", st.session_state.swagger_summary.get("Médios", 0))
            cols[4].metric("Baixos", st.session_state.swagger_summary.get("Baixos", 0))

        # Exibir detalhes das vulnerabilidades
        st.markdown(st.session_state.swagger_analysis_result_display)

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


def pentest_playbook_generator_page(llm_model_text):
    st.header("Pentest Playbook Generator 📖")
    st.markdown("""
        Descreva o escopo e os objetivos do seu pentest, e o HuntIA irá gerar um playbook
        com etapas sugeridas, ferramentas e considerações para cada fase do teste de intrusão.
        **ATENÇÃO:** Este playbook é um guia e deve ser adaptado à sua metodologia e ao ambiente real.
    """)
    logging.info("Página Pentest Playbook Generator acessada.")

    # Inicialização de variáveis de estado
    if 'playbook_scope' not in st.session_state:
        st.session_state.playbook_scope = ""
    if 'playbook_objectives' not in st.session_state:
        st.session_state.playbook_objectives = ""
    if 'playbook_output' not in st.session_state:
        st.session_state.playbook_output = ""

    def reset_playbook_generator():
        st.session_state.playbook_scope = ""
        st.session_state.playbook_objectives = ""
        st.session_state.playbook_output = ""
        logging.info("Pentest Playbook Generator: Reset de campos.")
        st.rerun()

    if st.button("Limpar Playbook", key="reset_playbook_button"):
        reset_playbook_generator()

    scope_input = st.text_area(
        "Escopo do Pentest (ex: 'Aplicação web e API REST', 'Rede interna', 'Ambiente de nuvem AWS'):",
        value=st.session_state.playbook_scope,
        placeholder="Ex: Sistema web de e-commerce, IP 192.168.1.0/24",
        height=100,
        key="playbook_scope_input"
    )
    st.session_state.playbook_scope = scope_input.strip()

    objectives_input = st.text_area(
        "Objetivos do Pentest (ex: 'Obter acesso a dados de clientes', 'Comprometer servidor web', 'Escalada de privilégios'):",
        value=st.session_state.playbook_objectives,
        placeholder="Ex: Identificar XSS e SQLi, testar controle de acesso, validar configurações de segurança",
        height=100,
        key="playbook_objectives_input"
    )
    st.session_state.playbook_objectives = objectives_input.strip()

    if st.button("Gerar Playbook", key="generate_playbook_button"):
        if not st.session_state.playbook_scope or not st.session_state.playbook_objectives:
            st.error("Por favor, forneça o escopo e os objetivos do pentest.")
            logging.warning("Pentest Playbook Generator: Geração abortada, escopo/objetivos vazios.")
            return
        else:
            with st.spinner("Gerando playbook de pentest..."):
                logging.info("Pentest Playbook Generator: Iniciando geração do playbook.")

                # --- INJETANDO O CONTEXTO GLOBAL ---
                global_context_prompt = get_global_context_prompt()
                # --- FIM INJEÇÃO DE CONTEXTO ---

                playbook_prompt = (
                    f"Você é um especialista em testes de intrusão, com profundo conhecimento em metodologias de pentest (OSSTMM, PTES, OWASP TOP 10, MITRE ATT&CK)."
                    f"{global_context_prompt}" # INJETANDO CONTEXTO GLOBAL
                    f"\n\nSua tarefa é gerar um playbook detalhado para um pentest com o seguinte escopo e objetivos:\n\n"
                    f"**Escopo:** {st.session_state.playbook_scope}\n"
                    f"**Objetivos:** {st.session_state.playbook_objectives}\n"
                    f"\n\nO playbook deve cobrir as principais fases de um pentest e, para cada fase/seção, incluir:\n"
                    f"- **Descrição:** O que esta fase envolve.\n"
                    f"- **Passos Chave:** Ações detalhadas a serem tomadas.\n"
                    f"- **Ferramentas Sugeridas:** Ferramentas específicas e comandos de exemplo (quando aplicável, em blocos de código markdown).\n"
                    f"- **Resultados Esperados:** O que procurar ou coletar.\n"
                    f"- **Considerações de Segurança/Ética:** Alertas e boas práticas.\n\n"
                    f"As fases a serem abordadas incluem (mas não se limitam a):"
                    f"1.  **Reconhecimento (Passivo e Ativo)**\n"
                    f"2.  **Mapeamento/Enumeração**\n"
                    f"3.  **Análise de Vulnerabilidades**\n"
                    f"4.  **Exploração**\n"
                    f"5.  **Pós-Exploração (Se aplicável, com foco em persistência, elevação de privilégios, movimento lateral, coleta de dados)**\n"
                    f"6.  **Geração de Relatório**\n\n"
                    f"Seja conciso, prático e acionável. Use Markdown para títulos e formatação clara. Inclua exemplos de comandos quando fizer sentido (ex: Nmap, dirb, SQLmap, Metasploit, etc.)."
                )

                playbook_raw = obter_resposta_llm(llm_model_text, [playbook_prompt])

                if playbook_raw:
                    st.session_state.playbook_output = playbook_raw
                    logging.info("Pentest Playbook Generator: Playbook gerado com sucesso.")
                else:
                    st.session_state.playbook_output = "Não foi possível gerar o playbook. Tente refinar o escopo e os objetivos."
                    logging.error("Pentest Playbook Generator: Falha na geração do playbook pelo LLM.")

    if st.session_state.playbook_output:
        st.subheader("Playbook de Pentest Gerado")
        st.markdown(st.session_state.playbook_output)
        
        # Botão para download
        st.download_button(
            label="Download Playbook (.md)",
            data=st.session_state.playbook_output.encode('utf-8'),
            file_name=f"pentest_playbook_{re.sub(r'[^a-zA-Z0-9_]', '', st.session_state.playbook_scope[:20])}_{int(time.time())}.md",
            mime="text/markdown",
            help="Baixa o playbook gerado em formato Markdown."
        )
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="playbook_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback Pentest Playbook Generator: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="playbook_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback Pentest Playbook Generator: Precisa de Melhoria.")


def intelligent_pentest_validator_page(llm_model_vision, llm_model_text):
    st.header("Intelligent Pentest Validator 📊")
    st.markdown("""
        Faça upload das evidências do seu pentest (prints de tela, resultados de ferramentas) com descrições.
        O HuntIA usará o LLM para analisar se o pentest cobriu o escopo/objetivos e sugerir melhorias.
    """)
    logging.info("Página Intelligent Pentest Validator acessada.")

    # Inicialização de variáveis de estado para a página
    if 'validation_scope' not in st.session_state: st.session_state.validation_scope = ""
    if 'validation_objectives' not in st.session_state: st.session_state.validation_objectives = ""
    if 'uploaded_evidences' not in st.session_state: st.session_state.uploaded_evidences = [] # Lista de {'image': Image.obj, 'description': str, 'name': str, 'id': str}
    if 'validation_llm_result' not in st.session_state: st.session_state.validation_llm_result = ""
    if 'validation_summary' not in st.session_state: st.session_state.validation_summary = None
    if 'overall_pentest_summary' not in st.session_state: st.session_state.overall_pentest_summary = ""

    def reset_validation():
        st.session_state.validation_scope = ""
        st.session_state.validation_objectives = ""
        st.session_state.uploaded_evidences = []
        st.session_state.validation_llm_result = ""
        st.session_state.validation_summary = None
        st.session_state.overall_pentest_summary = ""
        logging.info("Intelligent Pentest Validator: Reset de campos.")
        st.rerun()

    if st.button("Limpar e Nova Validação", key="reset_validation_button"):
        reset_validation()

    st.subheader("1. Defina o Escopo e Objetivos do Pentest")
    st.session_state.validation_scope = st.text_area(
        "Escopo do Pentest (Ex: 'Aplicação web de e-commerce', 'Rede interna com 10 hosts'):",
        value=st.session_state.validation_scope,
        placeholder="Ex: API REST de pagamentos, rede corporativa.",
        height=70,
        key="validation_scope_input"
    )

    st.session_state.validation_objectives = st.text_area(
        "Objetivos do Pentest (Ex: 'Identificar todas as injeções', 'Obter acesso de administrador', 'Validar hardening'):",
        value=st.session_state.validation_objectives,
        placeholder="Ex: Descobrir credenciais vazadas, testar falhas de lógica de negócio.",
        height=70,
        key="validation_objectives_input"
    )
    
    st.session_state.overall_pentest_summary = st.text_area(
        "Resumo Geral do Pentest (Opcional, mas útil para o LLM - Principais achados, metodologia utilizada, etc.):",
        value=st.session_state.overall_pentest_summary,
        placeholder="Ex: 'Pentest de caixa preta focado em OWASP Top 10. Encontrei 2 XSS, 1 IDOR e uma misconfiguration no Apache.'",
        height=150,
        key="overall_pentest_summary_input"
    )

    st.subheader("2. Faça Upload de Suas Evidências (Imagens e Descrições)")
    new_uploaded_files = st.file_uploader(
        "Adicione imagens de evidência (JPG, JPEG, PNG). Você pode adicionar várias de uma vez.",
        type=["jpg", "jpeg", "png"],
        accept_multiple_files=True,
        key="validation_evidence_uploader"
    )

    if new_uploaded_files:
        existing_file_fingerprints = {(e['name'], e['image'].size) for e in st.session_state.uploaded_evidences if 'name' in e and 'image' in e}
        
        for uploaded_file in new_uploaded_files:
            try:
                img_bytes = uploaded_file.getvalue()
                img = Image.open(BytesIO(img_bytes))
                
                file_fingerprint = (uploaded_file.name, img.size) 
                
                if file_fingerprint not in existing_file_fingerprints:
                    st.session_state.uploaded_evidences.append({
                        'image': img,
                        'description': "",
                        'name': uploaded_file.name,
                        'id': str(uuid.uuid4())
                    })
                    logging.info(f"Intelligent Pentest Validator: Evidência '{uploaded_file.name}' carregada.")
                else:
                    st.info(f"Arquivo '{uploaded_file.name}' já carregado. Ignorando duplicata.")
                    logging.info(f"Intelligent Pentest Validator: Evidência '{uploaded_file.name}' duplicada ignorada.")
            except Exception as e:
                st.error(f"Erro ao carregar a imagem {uploaded_file.name}: {e}")
                logging.error(f"Intelligent Pentest Validator: Erro ao carregar evidência '{uploaded_file.name}': {e}.")

    if st.session_state.uploaded_evidences:
        st.markdown("#### Evidências Carregadas:")
        evidences_to_remove = []
        for i, evidence in enumerate(st.session_state.uploaded_evidences):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.image(evidence['image'], caption=f"Evidência {i+1}: {evidence['name']}", use_container_width=True)
            with col2:
                description_key = f"evidence_description_{evidence['id']}"
                evidence['description'] = st.text_area(
                    "Descreva esta evidência (o que ela mostra?):",
                    value=evidence['description'],
                    key=description_key,
                    height=100
                )
                if st.button(f"Remover Evidência {i+1}", key=f"remove_evidence_btn_{evidence['id']}"):
                    evidences_to_remove.append(i)
        
        if evidences_to_remove:
            for index in sorted(evidences_to_remove, reverse=True):
                logging.info(f"Intelligent Pentest Validator: Evidência '{st.session_state.uploaded_evidences[index].get('name', 'N/A')}' removida.")
                del st.session_state.uploaded_evidences[index]
            st.rerun()

    st.subheader("3. Iniciar Validação do Pentest")
    if st.button("Validar Pentest com LLM", key="validate_pentest_button"):
        if not st.session_state.validation_scope:
            st.error("Por favor, preencha o escopo do pentest.")
            logging.warning("Intelligent Pentest Validator: Validação abortada, escopo vazio.")
            return
        if not st.session_state.validation_objectives:
            st.error("Por favor, preencha os objetivos do pentest.")
            logging.warning("Intelligent Pentest Validator: Validação abortada, objetivos vazios.")
            return
        elif not st.session_state.uploaded_evidences:
            st.error("Por favor, faça upload de pelo menos uma evidência.")
            logging.warning("Intelligent Pentest Validator: Validação abortada, nenhuma evidência carregada.")
            return
        else:
            with st.spinner("Realizando validação inteligente do pentest..."):
                logging.info(f"Intelligent Pentest Validator: Iniciando validação com {len(st.session_state.uploaded_evidences)} evidências.")

                # --- INJETANDO O CONTEXTO GLOBAL ---
                global_context_prompt = get_global_context_prompt()
                # --- FIM INJEÇÃO DE CONTEXTO ---

                llm_input_parts = [
                    f"Você é um revisor de qualidade de pentests e um especialista em segurança. "
                    f"{global_context_prompt}" # INJETANDO CONTEXTO GLOBAL
                    f"\n\nSua tarefa é analisar o escopo, os objetivos e as evidências (imagens com descrições) de um pentest, e fornecer uma avaliação detalhada da sua completude e qualidade."
                    f"**Escopo do Pentest:** {st.session_state.validation_scope}\n"
                    f"**Objetivos:** {st.session_state.validation_objectives}\n"
                    f"**Resumo Geral do Pentest (Fornecido pelo Pentester):** {st.session_state.overall_pentest_summary if st.session_state.overall_pentest_summary else 'Nenhum resumo geral fornecido.'}\n"
                    f"\n\n**Instruções para Análise:**\n"
                    f"1.  **Avalie a Cobertura:** Com base no escopo e objetivos, avalie se as evidências indicam que o pentest cobriu as áreas esperadas.\n"
                    f"2.  **Qualidade das Evidências:** Avalie se as evidências são claras, suficientes e relevantes para comprovar as atividades/achados.\n"
                    f"3.  **Identifique Lacunas:** Aponte explicitamente qualquer área que pareça ter sido negligenciada, insuficientemente testada ou mal documentada, dada a natureza do pentest.\n"
                    f"4.  **Sugestões de Melhoria:** Forneça sugestões concretas para melhorar o pentest ou a documentação, incluindo possíveis ferramentas ou técnicas adicionais.\n"
                    f"5.  **Critique a Exploração/Documentação de Vulnerabilidades:** Se vulnerabilidades são mencionadas, avalie se a exploração parece completa e se há PoCs claras.\n\n"
                    f"**Formato da Resposta:**\n"
                    f"**RESUMO GERAL DO STATUS DO PENTEST:** Forneça um resumo quantitativo na PRIMEIRA LINHA da sua resposta, no formato exato: `Total de Achados de Validação: X | Cobertura Alta: Y | Cobertura Média: Z | Cobertura Baixa: W | Lacunas: V` (substitua X,Y,Z,W,V pelos números correspondentes). 'Total de Achados de Validação' refere-se aos pontos de feedback. 'Cobertura' refere-se à abrangência do pentest, e 'Lacunas' são as áreas que faltaram.\n\n"
                    f"Para cada ponto de feedback, use o seguinte formato Markdown:\n"
                    f"## [Tipo de Feedback] (Ex: Cobertura OK, Lacuna Identificada, Sugestão de Melhoria)\n"
                    f"**Categoria:** [Cobertura/Qualidade/Lacuna/Sugestão/Vulnerabilidade Específica]\n"
                    f"**Nível de Importância:** [Crítico/Alto/Médio/Baixo/Informativo]\n"
                    f"**Detalhes:** [Explique o feedback, referenciando as evidências por 'Evidência [Número da Imagem]' e sua descrição. Ex: 'Evidência 3 ('Scan de Nmap') mostra uma boa cobertura de portas, indicando um reconhecimento ativo sólido.']\n"
                    f"**Recomendação/Ação:** [Sugira o que deve ser feito para resolver uma lacuna ou melhorar um ponto. Inclua ferramentas/comandos se aplicável.]\n\n"
                    f"--- Evidências Fornecidas ---\n"
                ]

                for i, evidence in enumerate(st.session_state.uploaded_evidences):
                    llm_input_parts.append(f"Evidência {i+1} (Nome: {evidence['name']}): {evidence['description']}\n")
                    llm_input_parts.append(evidence['image'])
                
                validation_raw_result = obter_resposta_llm(llm_model_vision, llm_input_parts)

                if validation_raw_result:
                    st.session_state.validation_summary, st.session_state.validation_llm_result = parse_vulnerability_summary(validation_raw_result)
                    if st.session_state.validation_summary:
                        st.session_state.validation_summary_display = {
                            "Total de Achados de Validação": st.session_state.validation_summary.get("Total", 0),
                            "Cobertura Alta": st.session_state.validation_summary.get("Cobertura Alta", 0),
                            "Cobertura Média": st.session_state.validation_summary.get("Cobertura Média", 0),
                            "Cobertura Baixa": st.session_state.validation_summary.get("Cobertura Baixa", 0),
                            "Lacunas": st.session_state.validation_summary.get("Lacunas", 0)
                        }
                    logging.info("Intelligent Pentest Validator: Validação concluída com sucesso.")
                else:
                    st.session_state.validation_llm_result = "Não foi possível obter a validação do pentest. Tente refinar as informações."
                    st.session_state.validation_summary = None
                    logging.error("Intelligent Pentest Validator: Falha na obtenção da validação do LLM.")

    if st.session_state.validation_llm_result:
        st.subheader("Resultados da Validação do Pentest")
        if st.session_state.validation_summary and getattr(st.session_state, 'validation_summary_display', None):
            cols = st.columns(5)
            cols[0].metric("Total Achados", st.session_state.validation_summary_display["Total de Achados de Validação"])
            cols[1].metric("Cobertura Alta", st.session_state.validation_summary_display["Cobertura Alta"])
            cols[2].metric("Cobertura Média", st.session_state.validation_summary_display["Cobertura Média"])
            cols[3].metric("Cobertura Baixa", st.session_state.validation_summary_display["Cobertura Baixa"])
            cols[4].metric("Lacunas", st.session_state.validation_summary_display["Lacunas"])
            st.markdown("---")
        else:
            st.warning("Não foi possível exibir o resumo da validação. Formato inesperado do LLM ou erro na análise.")

        st.markdown(st.session_state.validation_llm_result)
        
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="validation_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
            logging.info("Feedback Intelligent Pentest Validator: Útil.")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="validation_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")
            logging.info("Feedback Intelligent Pentest Validator: Precisa de Melhoria.")



def pentest_narrative_generator_page(llm_model_vision, llm_model_text):
    st.header("Pentest Narrative Generator 📝")
    st.markdown("""
        Gere uma narrativa de relatório de pentest abrangente e profissional, combinando
        detalhes do cliente/aplicação com suas evidências de teste, agora categorizadas por fase do pentest.
        O HuntIA irá integrar e expandir seus achados em um texto completo, incluindo uma conclusão e
        referências às imagens que você anexou.
    """)
    logging.info("Página Pentest Narrative Generator acessada.")

    # Variáveis de sessão para esta página
    if 'narrative_client_name' not in st.session_state: st.session_state.narrative_client_name = ""
    if 'narrative_app_name' not in st.session_state: st.session_state.narrative_app_name = ""
    if 'narrative_pentest_type' not in st.session_state: st.session_state.narrative_pentest_type = "Web Application"

    # NOVOS: Listas separadas para evidências por categoria
    if 'narrative_recon_evidences' not in st.session_state: st.session_state.narrative_recon_evidences = [] # [{'image': Image, 'description': '', 'report_image_filename': '', 'raw_tool_output': '', 'id': uuid}]
    if 'narrative_vuln_evidences' not in st.session_state: st.session_state.narrative_vuln_evidences = [] # [{'image': Image, 'vulnerability_name': '', 'severity': '', 'description': '', 'report_image_filename': '', 'raw_tool_output': '', 'id': uuid}]
    if 'narrative_resilience_evidences' not in st.session_state: st.session_state.narrative_resilience_evidences = [] # [{'image': Image, 'test_name': '', 'description': '', 'report_image_filename': '', 'raw_tool_output': '', 'id': uuid}]

    if 'generated_narrative_output' not in st.session_state: st.session_state.generated_narrative_output = ""
    if 'narrative_summary_output' not in st.session_state: st.session_state.narrative_summary_output = ""


    def reset_narrative_generator():
        st.session_state.narrative_client_name = ""
        st.session_state.narrative_app_name = ""
        st.session_state.narrative_pentest_type = "Web Application"
        st.session_state.narrative_recon_evidences = [] # Reset das novas listas
        st.session_state.narrative_vuln_evidences = []
        st.session_state.narrative_resilience_evidences = []
        st.session_state.generated_narrative_output = ""
        st.session_state.narrative_summary_output = ""
        logging.info("Pentest Narrative Generator: Reset de campos.")
        st.rerun()

    if st.button("Limpar e Gerar Nova Narrativa", key="reset_narrative_button"):
        reset_narrative_generator()

    st.subheader("1. Detalhes do Projeto")
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

    st.subheader("2. Upload e Detalhamento das Evidências por Categoria")
    st.info("Para cada seção, faça upload de imagens e detalhe os achados. O nome do arquivo da imagem será usado para referência no relatório.")

    # --- Seção de Evidências de Reconhecimento e Mapeamento ---
    st.markdown("#### Evidências de Reconhecimento e Mapeamento")
    new_recon_files = st.file_uploader(
        "Adicionar imagens para Reconhecimento e Mapeamento:",
        type=["jpg", "jpeg", "png"],
        accept_multiple_files=True,
        key="recon_evidence_uploader"
    )
    if new_recon_files:
        existing_fingerprints = {(e['name'], e['image'].size) for e in st.session_state.narrative_recon_evidences if 'name' in e and 'image' in e}
        for uploaded_file in new_recon_files:
            try:
                img_bytes = uploaded_file.getvalue()
                img = Image.open(BytesIO(img_bytes))
                file_fingerprint = (uploaded_file.name, img.size)
                if file_fingerprint not in existing_fingerprints:
                    st.session_state.narrative_recon_evidences.append({
                        'image': img, 'description': '', 'report_image_filename': uploaded_file.name,
                        'raw_tool_output': '', 'id': str(uuid.uuid4()), 'name': uploaded_file.name
                    })
                    logging.info(f"Narrative Generator: Recon evidence '{uploaded_file.name}' loaded.")
                else: st.info(f"Arquivo '{uploaded_file.name}' já carregado (Recon).")
            except Exception as e: st.error(f"Erro ao carregar imagem para Recon: {e}"); logging.error(f"Narrative Generator: Error loading recon image: {e}.")
    
    recon_evidences_to_remove = []
    for i, evidence in enumerate(st.session_state.narrative_recon_evidences):
        st.markdown(f"**Recon Evidência {i+1}:** `{evidence['name']}`")
        st.image(evidence['image'], use_container_width=True)
        st.session_state.narrative_recon_evidences[i]['description'] = st.text_area(
            "Descrição do Achado de Reconhecimento:", value=evidence['description'],
            placeholder="Ex: 'Esta imagem mostra os subdomínios descobertos via OSINT, incluindo dev.exemplo.com.'",
            key=f"recon_desc_{evidence['id']}", height=70
        )
        st.session_state.narrative_recon_evidences[i]['report_image_filename'] = st.text_input(
            "Nome do Arquivo da Imagem (Ex: `subdominios.png`):", value=evidence['report_image_filename'],
            placeholder="nome-da-imagem.jpg", key=f"recon_filename_{evidence['id']}"
        )
        st.session_state.narrative_recon_evidences[i]['raw_tool_output'] = st.text_area(
            "Output Bruto da Ferramenta (Opcional para Recon):", value=evidence['raw_tool_output'],
            placeholder="Cole o output do Subfinder/Nmap/etc. aqui.",
            key=f"recon_raw_output_{evidence['id']}", height=100
        )
        if st.button(f"Remover Recon Evidência {i+1}", key=f"remove_recon_evidence_btn_{evidence['id']}"): recon_evidences_to_remove.append(i)
    for index in sorted(recon_evidences_to_remove, reverse=True): del st.session_state.narrative_recon_evidences[index]; st.rerun()

    # --- Seção de Evidências de Vulnerabilidades Encontradas ---
    st.markdown("---")
    st.markdown("#### Evidências de Vulnerabilidades Encontradas")
    new_vuln_files = st.file_uploader(
        "Adicionar imagens para Vulnerabilidades Encontradas:",
        type=["jpg", "jpeg", "png"],
        accept_multiple_files=True,
        key="vuln_evidence_uploader"
    )
    if new_vuln_files:
        existing_fingerprints = {(e['name'], e['image'].size) for e in st.session_state.narrative_vuln_evidences if 'name' in e and 'image' in e}
        for uploaded_file in new_vuln_files:
            try:
                img_bytes = uploaded_file.getvalue()
                img = Image.open(BytesIO(img_bytes))
                file_fingerprint = (uploaded_file.name, img.size)
                if file_fingerprint not in existing_fingerprints:
                    st.session_state.narrative_vuln_evidences.append({
                        'image': img, 'vulnerability_name': '', 'severity': 'Média',
                        'description': '', 'report_image_filename': uploaded_file.name,
                        'raw_tool_output': '', 'id': str(uuid.uuid4()), 'name': uploaded_file.name
                    })
                    logging.info(f"Narrative Generator: Vuln evidence '{uploaded_file.name}' loaded.")
                else: st.info(f"Arquivo '{uploaded_file.name}' já carregado (Vuln).")
            except Exception as e: st.error(f"Erro ao carregar imagem para Vuln: {e}"); logging.error(f"Narrative Generator: Error loading vuln image: {e}.")

    vuln_evidences_to_remove = []
    for i, evidence in enumerate(st.session_state.narrative_vuln_evidences):
        st.markdown(f"**Vulnerabilidade Evidência {i+1}:** `{evidence['name']}`")
        st.image(evidence['image'], use_container_width=True)
        st.session_state.narrative_vuln_evidences[i]['vulnerability_name'] = st.text_input(
            "Nome da Vulnerabilidade:", value=evidence['vulnerability_name'],
            placeholder="Ex: Clickjacking, SQL Injection", key=f"vuln_name_{evidence['id']}"
        )
        st.session_state.narrative_vuln_evidences[i]['severity'] = st.selectbox(
            "Severidade da Vulnerabilidade:", options=["Crítica", "Alta", "Média", "Baixa", "Informativa"],
            index=["Crítica", "Alta", "Média", "Baixa", "Informativa"].index(evidence['severity']),
            key=f"vuln_severity_{evidence['id']}"
        )
        st.session_state.narrative_vuln_evidences[i]['description'] = st.text_area(
            "Descrição do Problema (como foi explorada, impacto):", value=evidence['description'],
            placeholder="Ex: 'Foi possível sobrepor a página de login e induzir cliques no botão de submissão, evidência de Clickjacking.'",
            key=f"vuln_desc_{evidence['id']}", height=100
        )
        st.session_state.narrative_vuln_evidences[i]['report_image_filename'] = st.text_input(
            "Nome do Arquivo da Imagem (Ex: `clickjacking_poc.png`):", value=evidence['report_image_filename'],
            placeholder="nome-da-imagem.jpg", key=f"vuln_filename_{evidence['id']}"
        )
        st.session_state.narrative_vuln_evidences[i]['raw_tool_output'] = st.text_area(
            "Output Bruto da Ferramenta (Opcional para Vuln):", value=evidence['raw_tool_output'],
            placeholder="Cole o output do Burp, Acunetix, etc. aqui.",
            key=f"vuln_raw_output_{evidence['id']}", height=100
        )
        if st.button(f"Remover Vuln Evidência {i+1}", key=f"remove_vuln_evidence_btn_{evidence['id']}"): vuln_evidences_to_remove.append(i)
    for index in sorted(vuln_evidences_to_remove, reverse=True): del st.session_state.narrative_vuln_evidences[index]; st.rerun()

    # --- Seção de Evidências de Testes de Resiliência (Sem Falha) ---
    st.markdown("---")
    st.markdown("#### Evidências de Testes de Resiliência (Sem Falha)")
    new_resilience_files = st.file_uploader(
        "Adicionar imagens para Testes de Resiliência:",
        type=["jpg", "jpeg", "png"],
        accept_multiple_files=True,
        key="resilience_evidence_uploader"
    )
    if new_resilience_files:
        existing_fingerprints = {(e['name'], e['image'].size) for e in st.session_state.narrative_resilience_evidences if 'name' in e and 'image' in e}
        for uploaded_file in new_resilience_files:
            try:
                img_bytes = uploaded_file.getvalue()
                img = Image.open(BytesIO(img_bytes))
                file_fingerprint = (uploaded_file.name, img.size)
                if file_fingerprint not in existing_fingerprints:
                    st.session_state.narrative_resilience_evidences.append({
                        'image': img, 'test_name': '', 'description': '',
                        'report_image_filename': uploaded_file.name, 'raw_tool_output': '',
                        'id': str(uuid.uuid4()), 'name': uploaded_file.name
                    })
                    logging.info(f"Narrative Generator: Resilience evidence '{uploaded_file.name}' loaded.")
                else: st.info(f"Arquivo '{uploaded_file.name}' já carregado (Resilience).")
            except Exception as e: st.error(f"Erro ao carregar imagem para Resiliência: {e}"); logging.error(f"Narrative Generator: Error loading resilience image: {e}.")

    resilience_evidences_to_remove = []
    for i, evidence in enumerate(st.session_state.narrative_resilience_evidences):
        st.markdown(f"**Resiliência Evidência {i+1}:** `{evidence['name']}`")
        st.image(evidence['image'], use_container_width=True)
        st.session_state.narrative_resilience_evidences[i]['test_name'] = st.text_input(
            "Nome do Teste de Resiliência:", value=evidence['test_name'],
            placeholder="Ex: Validação de Proteção contra Clickjacking, Teste de CORS", key=f"resilience_test_name_{evidence['id']}"
        )
        st.session_state.narrative_resilience_evidences[i]['description'] = st.text_area(
            "Descrição do Teste e Resultado Positivo (como a aplicação demonstrou resiliência):", value=evidence['description'],
            placeholder="Ex: 'Esta imagem mostra que o cabeçalho X-Frame-Options está configurado corretamente, impedindo o Clickjacking.'",
            key=f"resilience_desc_{evidence['id']}", height=100
        )
        st.session_state.narrative_resilience_evidences[i]['report_image_filename'] = st.text_input(
            "Nome do Arquivo da Imagem (Ex: `cors_ok.png`):", value=evidence['report_image_filename'],
            placeholder="nome-da-imagem.jpg", key=f"resilience_filename_{evidence['id']}"
        )
        st.session_state.narrative_resilience_evidences[i]['raw_tool_output'] = st.text_area(
            "Output Bruto da Ferramenta (Opcional para Resiliência):", value=evidence['raw_tool_output'],
            placeholder="Cole o output do teste aqui (ex: cabeçalho de resposta HTTP).",
            key=f"resilience_raw_output_{evidence['id']}", height=100
        )
        if st.button(f"Remover Resiliência Evidência {i+1}", key=f"remove_resilience_evidence_btn_{evidence['id']}"): resilience_evidences_to_remove.append(i)
    for index in sorted(resilience_evidences_to_remove, reverse=True): del st.session_state.narrative_resilience_evidences[index]; st.rerun()

    st.subheader("3. Gerar Narrativa")
    if st.button("Gerar Narrativa de Pentest", key="generate_narrative_button"):
        if not st.session_state.narrative_client_name or not st.session_state.narrative_app_name:
            st.error("Por favor, preencha o Nome do Cliente e o Nome da Aplicação.")
            logging.warning("Narrative Generator: Geração abortada, dados do projeto incompletos.")
            return
        
        # Validar que pelo menos UMA evidência de qualquer tipo foi adicionada
        if not (st.session_state.narrative_recon_evidences or st.session_state.narrative_vuln_evidences or st.session_state.narrative_resilience_evidences):
            st.error("Por favor, adicione pelo menos uma evidência em qualquer uma das categorias.")
            logging.warning("Narrative Generator: Geração abortada, nenhuma evidência adicionada.")
            return

        # Validação mais detalhada de cada evidência antes de enviar ao LLM
        for i, evidence in enumerate(st.session_state.narrative_recon_evidences):
            if not evidence['description'] or not evidence['report_image_filename']:
                st.error(f"Reconhecimento Evidência {i+1}: Por favor, preencha a descrição e o nome do arquivo da imagem.")
                logging.warning(f"Narrative Generator: Recon evidence {i+1} incomplete.")
                return
        for i, evidence in enumerate(st.session_state.narrative_vuln_evidences):
            if not evidence['vulnerability_name'] or not evidence['description'] or not evidence['report_image_filename']:
                st.error(f"Vulnerabilidade Evidência {i+1}: Por favor, preencha o nome, descrição e o nome do arquivo da imagem.")
                logging.warning(f"Narrative Generator: Vuln evidence {i+1} incomplete.")
                return
        for i, evidence in enumerate(st.session_state.narrative_resilience_evidences):
            if not evidence['test_name'] or not evidence['description'] or not evidence['report_image_filename']:
                st.error(f"Resiliência Evidência {i+1}: Por favor, preencha o nome do teste, descrição e o nome do arquivo da imagem.")
                logging.warning(f"Narrative Generator: Resilience evidence {i+1} incomplete.")
                return

        with st.spinner("Gerando narrativa de pentest..."):
            logging.info(f"Narrative Generator: Iniciando geração para {st.session_state.narrative_client_name}/{st.session_state.narrative_app_name}.")

            # --- MODELO DE NARRATIVA BASE ---
            narrative_template = f"""
## Introdução

Foram conduzidos testes de segurança abrangentes com o objetivo de avaliar a robustez e a segurança da aplicação **{st.session_state.narrative_app_name}** pertencente ao cliente **{st.session_state.narrative_client_name}**. Durante essa avaliação, foram executadas diversas Provas de Conceito (PoCs) para identificar possíveis vulnerabilidades, com base nos padrões da **OWASP Top 10**, **OWASP Mobile Top 10 (2024)** e nas melhores práticas da **Pentest Execution Standard (PTES)**.

Esses testes visaram localizar vulnerabilidades que poderiam comprometer a confidencialidade, integridade ou disponibilidade da aplicação, permitindo uma análise detalhada dos riscos potenciais e auxiliando na implementação de medidas de correção e mitigação.

## Achados de Reconhecimento e Mapeamento

## Vulnerabilidades Identificadas e Detalhamento

## Verificações de Segurança e Resiliência

## Conclusão e Recomendações Finais

"""

            # Prepara as evidências CATEGORIZADAS para o LLM
            categorized_evidences_for_llm = {
                "recon_evidences": [],
                "vuln_evidences": [],
                "resilience_evidences": []
            }

            for i, ev in enumerate(st.session_state.narrative_recon_evidences):
                categorized_evidences_for_llm["recon_evidences"].append(
                    f"RECONHECIMENTO EVIDÊNCIA {i+1}:\n"
                    f"Descrição: {ev['description']}\n"
                    f"Nome do arquivo da imagem: {ev['report_image_filename']}\n"
                    f"Output Bruto da Ferramenta: {'(Nenhum fornecido)' if not ev['raw_tool_output'] else ev['raw_tool_output']}\n"
                    f"--------------------"
                )
            
            for i, ev in enumerate(st.session_state.narrative_vuln_evidences):
                categorized_evidences_for_llm["vuln_evidences"].append(
                    f"VULNERABILIDADE EVIDÊNCIA {i+1}:\n"
                    f"Nome da Vulnerabilidade: {ev['vulnerability_name']}\n"
                    f"Severidade: {ev['severity']}\n"
                    f"Descrição do Problema: {ev['description']}\n"
                    f"Nome do arquivo da imagem: {ev['report_image_filename']}\n"
                    f"Output Bruto da Ferramenta: {'(Nenhum fornecido)' if not ev['raw_tool_output'] else ev['raw_tool_output']}\n"
                    f"--------------------"
                )
            
            for i, ev in enumerate(st.session_state.narrative_resilience_evidences):
                categorized_evidences_for_llm["resilience_evidences"].append(
                    f"RESILIÊNCIA EVIDÊNCIA {i+1}:\n"
                    f"Nome do Teste: {ev['test_name']}\n"
                    f"Descrição do Teste e Resultado Positivo: {ev['description']}\n"
                    f"Nome do arquivo da imagem: {ev['report_image_filename']}\n"
                    f"Output Bruto da Ferramenta: {'(Nenhum fornecido)' if not ev['raw_tool_output'] else ev['raw_tool_output']}\n"
                    f"--------------------"
                )

            # --- INÍCIO DA MELHORIA: TÉCNICA FEW-SHOT PROMPTING ---
            exemplo_de_qualidade = """
**EXEMPLO DE REFERÊNCIA DE ALTA QUALIDADE (NÃO INCLUA ESTE EXEMPLO NA SAÍDA FINAL):**
'### Cross-Site Scripting (XSS) Refletido
Durante a fase de exploração, foi identificado que o parâmetro 'query' na URL de busca não sanitizava adequadamente a entrada do usuário. Ao injetar o payload `<script>alert('XSS by HuntIA')</script>`, foi possível executar código JavaScript arbitrário no contexto do navegador da vítima, como evidenciado na imagem `xss_poc.png`. Esta falha é classificada como **Média** e pode levar ao roubo de cookies de sessão, phishing e desfiguração da página.
**Recomendação:** A mitigação requer a implementação de Output Encoding em todas as saídas de dados que refletem a entrada do usuário. Especificamente, caracteres como `<`, `>`, `"` devem ser convertidos para suas entidades HTML (`&lt;`, `&gt;`, `&quot;`).'
"""
            # --- FIM DA MELHORIA ---

            global_context_prompt = get_global_context_prompt()

            prompt_instructions = (
                f"Você é um especialista em segurança da informação e pentest, com vasta experiência na redação de relatórios técnicos de pentest."
                f"{global_context_prompt}"
                f"\n\n{exemplo_de_qualidade}" # Adicionando o exemplo de alta qualidade
                f"\n\nUse o exemplo acima como um guia para o nível de detalhe, tom técnico e formato que você deve seguir ao descrever cada vulnerabilidade."
                f"\n\nSua tarefa é gerar uma narrativa de relatório de pentest abrangente e profissional para a aplicação '{st.session_state.narrative_app_name}' do cliente '{st.session_state.narrative_client_name}'. "
                f"O tipo principal de pentest é '{st.session_state.narrative_pentest_type}'. Ajuste sua linguagem, o foco das vulnerabilidades e prioridade de achados a isso."
                f"\n\nVocê receberá um modelo de narrativa com seções principais e **evidências pré-categorizadas** (Reconhecimento, Vulnerabilidades, Resiliência). Seu objetivo é:"
                f"\n1.  **Preencher e Expandir as seções principais do modelo** com base nas evidências fornecidas em cada categoria. Mantenha os títulos das seções principais (`## Introdução`, `## Achados de Reconhecimento e Mapeamento`, etc.) exatamente como estão."
                f"\n2.  Para cada **evidência de 'RECONHECIMENTO E MAPEAMENTO'**: Use a 'Descrição' e o 'Output Bruto da Ferramenta' (se fornecido) para elaborar um parágrafo detalhado sobre a atividade de reconhecimento e seus achados. Insira a referência da imagem no formato `![](/images/name/[nome_do_arquivo_da_imagem]){{width=\"auto\"}}` logo abaixo do parágrafo que a descreve."
                f"\n3.  Para cada **evidência de 'VULNERABILIDADE'**: Crie um subtítulo `### [Nome da Vulnerabilidade]`. Descreva a vulnerabilidade em termos gerais. Utilize a 'Descrição do Problema' e o 'Output Bruto da Ferramenta' (se fornecido) para detalhar como a falha se manifestou/foi explorada e seu impacto. Forneça o impacto técnico/de negócio e uma recomendação técnica clara para mitigação. Insira a referência da imagem no formato `![](/images/name/[nome_do_arquivo_da_imagem]){{width=\"auto\"}}` logo abaixo do parágrafo. Classifique a severidade."
                f"\n4.  Para cada **evidência de 'RESILIÊNCIA'**: Crie um subtítulo `### [Nome do Teste]`. Descreva o teste realizado e seu objetivo. Utilize a 'Descrição do Teste e Resultado Positivo' e o 'Output Bruto da Ferramenta' (se fornecido) para detalhar como a aplicação demonstrou resiliência, explicando os controles que impediram a exploração. Destaque as boas práticas. Insira a referência da imagem no formato `![](/images/name/[nome_do_arquivo_da_imagem]){{width=\"auto\"}}` logo abaixo do parágrafo."
                f"\n5.  **Organize os achados/testes nas seções correspondentes**. Priorize vulnerabilidades de maior severidade primeiro dentro de suas seções."
                f"\n6.  A seção **'Conclusão e Recomendações Finais' deve ser a ÚLTIMA seção e aparecer APENAS UMA VEZ no documento.** Resuma o estado geral de segurança da aplicação, destacando pontos fortes (resiliência) e áreas que exigem atenção (vulnerabilidades) e recomendações contínuas, baseadas em *todos* os achados."
                f"\n7.  **Mantenha um tom técnico, claro, conciso e profissional em toda a narrativa.**"
                f"\n8.  **Não inclua quaisquer notas adicionais, cabeçalhos de LLM, ou formatações extras que não sejam a narrativa final do relatório.**"
                f"\n\n--- Modelo de Seções do Relatório ---\n"
                + f"{narrative_template}" + # Injetando o template predefinido aqui
                f"\n--- Evidências de Reconhecimento (para preencher o modelo) ---\n" +
                "\n".join(categorized_evidences_for_llm["recon_evidences"]) +
                f"\n--- Evidências de Vulnerabilidades (para preencher o modelo) ---\n" +
                "\n".join(categorized_evidences_for_llm["vuln_evidences"]) +
                f"\n--- Evidências de Resiliência (para preencher o modelo) ---\n" +
                "\n".join(categorized_evidences_for_llm["resilience_evidences"])
            )

            # A lógica de geração e extração da conclusão permanece a mesma
            generated_text_raw = obter_resposta_llm(llm_model_text, [prompt_instructions])

            if generated_text_raw:
                st.session_state.generated_narrative_output = generated_text_raw.strip()
                
                conclusion_match = re.search(r"## Conclusão e Recomendações Finais\n(.*?)(?=(## |\Z))", st.session_state.generated_narrative_output, re.DOTALL)
                if conclusion_match:
                    st.session_state.narrative_summary_output = conclusion_match.group(1).strip()
                else:
                    st.session_state.narrative_summary_output = "Conclusão não detectada ou formatada incorretamente na narrativa. Por favor, verifique a narrativa completa."
                
                st.success("Narrativa de pentest gerada com sucesso!")
                logging.info("Pentest Narrative Generator: Narrativa gerada com sucesso.")
            else:
                st.session_state.generated_narrative_output = "Não foi possível gerar a narrativa. Tente novamente ou ajuste as entradas."
                st.session_state.narrative_summary_output = ""
                logging.error("Pentest Narrative Generator: Falha na geração da narrativa pelo LLM.")
    
    if st.session_state.generated_narrative_output:
        st.subheader("Narrativa de Pentest Gerada:")
        st.markdown(st.session_state.generated_narrative_output)

        if st.session_state.narrative_summary_output:
            st.markdown("---")
            st.subheader("Conclusão da Análise (Extraída):")
            st.markdown(st.session_state.narrative_summary_output)

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

    # Inicializa todos os estados globais na primeira execução para evitar erros
    if 'global_profile' not in st.session_state: st.session_state.global_profile = "Nenhum"
    if 'global_scenario' not in st.session_state: st.session_state.global_scenario = "Nenhum"
    if 'projeto_ativo_id' not in st.session_state: st.session_state.projeto_ativo_id = None
    if 'projeto_ativo_nome' not in st.session_state: st.session_state.projeto_ativo_nome = None
    if 'modo_rascunho' not in st.session_state: st.session_state.modo_rascunho = True # Inicia em modo rascunho por padrão
    
    with st.sidebar:
        # Adiciona um status rápido e limpo na sidebar para o usuário sempre saber como está operando
        st.markdown("##### Modo de Operação")
        if st.session_state.get('modo_rascunho', True):
            st.info("Modo Rascunho ✏️")
        elif st.session_state.get('projeto_ativo_nome'):
            st.success(f"Projeto: {st.session_state.projeto_ativo_nome}")
        else:
            # Este aviso incentiva o usuário a ir para as configurações
            st.warning("Nenhum projeto selecionado.")
        st.markdown("---")
            
        selected = option_menu(
            menu_title="Navegação Principal",
            options=[
                "Início",
                "Configurações", # <-- NOVA PÁGINA
                "Correlation Dashboard",
                "OWASP Vulnerability Details",
                "Deep HTTP Insight",
                "OWASP Image Analyzer",
                "PoC Generator (HTML)",
                "OpenAPI Analyzer",
                "Static Code Analyzer",
                "Tactical Command Orchestrator",
                "Pentest Playbook Generator",
                "Intelligent Pentest Validator",
                "Pentest Narrative Generator",
                "Mobile Static Analyzer"
            ],
            icons=[
                "house", "gear-fill", # <-- NOVO ÍCONE
                "diagram-3", "bug", "globe", "image", "file-earmark-code",
                "file-earmark-richtext", "code-slash", "terminal",
                "book", "check-square", "file-earmark-text", "phone"
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
        settings_page() # <-- ROTA PARA A NOVA PÁGINA
    elif selected == "Correlation Dashboard":
        correlation_dashboard_page(llm_model_text)
    elif selected == "OWASP Vulnerability Details":
        owasp_text_analysis_page(llm_model_vision, llm_model_text)
    elif selected == "Deep HTTP Insight":
        http_request_analysis_page(llm_model_vision, llm_model_text)
    elif selected == "OWASP Image Analyzer":
        owasp_scout_visual_page(llm_model_vision, llm_model_text)
    elif selected == "PoC Generator (HTML)":
        poc_generator_html_page(llm_model_vision, llm_model_text)
    elif selected == "OpenAPI Analyzer":
        swagger_openapi_analyzer_page(llm_model_vision, llm_model_text)
    elif selected == "Static Code Analyzer":
        static_code_analyzer_page(llm_model_vision, llm_model_text)
    elif selected == "Tactical Command Orchestrator":
        tactical_command_orchestrator_page(llm_model_text)
    elif selected == "Pentest Playbook Generator":
        pentest_playbook_generator_page(llm_model_text)
    elif selected == "Intelligent Pentest Validator":
        intelligent_pentest_validator_page(llm_model_vision, llm_model_text)
    elif selected == "Pentest Narrative Generator":
        pentest_narrative_generator_page(llm_model_vision, llm_model_text)
    elif selected == "Mobile Static Analyzer":
        mobile_app_static_analysis_page(llm_model_vision, llm_model_text)

if __name__ == "__main__":
    main()