import sqlite3
import logging

# Define o nome do arquivo do banco de dados. Ele será criado na mesma pasta.
DB_NAME = "huntia_projects.db"

def init_db():
    """
    Cria as tabelas do banco de dados se elas ainda não existirem.
    Esta função é segura para ser chamada toda vez que o aplicativo inicia.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Tabela para guardar os nomes dos projetos
        c.execute('''
            CREATE TABLE IF NOT EXISTS projetos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome_projeto TEXT NOT NULL UNIQUE,
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela para guardar os dados de cada análise, com uma chave estrangeira para o projeto
        c.execute('''
            CREATE TABLE IF NOT EXISTS analises (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                projeto_id INTEGER NOT NULL,
                tipo_analise TEXT NOT NULL,
                resumo_input TEXT,
                resultado_completo TEXT,
                data_analise TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (projeto_id) REFERENCES projetos (id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
        conn.close()
        logging.info("Banco de dados 'huntia_projects.db' inicializado com sucesso.")
    except Exception as e:
        logging.error(f"Erro ao inicializar o banco de dados: {e}")

def criar_projeto(nome_projeto):
    """
    Adiciona um novo projeto ao banco de dados.
    VERSÃO CORRIGIDA: Agora retorna 3 valores em todos os cenários:
    (True/False, id_do_projeto, Mensagem).
    """
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        c = conn.cursor()
        c.execute("INSERT INTO projetos (nome_projeto) VALUES (?)", (nome_projeto,))
        
        # Pega o ID da linha que acabamos de inserir de forma segura.
        novo_id = c.lastrowid
        
        conn.commit()
        conn.close()
        logging.info(f"Projeto '{nome_projeto}' (ID: {novo_id}) criado com sucesso.")
        # Retorna 3 valores em caso de sucesso
        return True, novo_id, f"Projeto '{nome_projeto}' criado!"
    except sqlite3.IntegrityError:
        logging.warning(f"Tentativa de criar projeto duplicado: '{nome_projeto}'.")
        # Retorna 3 valores em caso de erro de duplicata
        return False, None, f"O nome de projeto '{nome_projeto}' já existe."
    except Exception as e:
        error_message = f"Erro de Banco de Dados: {str(e)}"
        logging.error(f"Erro ao criar projeto '{nome_projeto}': {e}", exc_info=True)
        # Retorna 3 valores em caso de outro erro
        return False, None, error_message

def listar_projetos():
    """Retorna uma lista de tuplas, onde cada tupla é (id, nome_projeto)."""
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id, nome_projeto FROM projetos ORDER BY nome_projeto ASC")
        projetos = c.fetchall()
        conn.close()
        return projetos
    except Exception as e:
        logging.error(f"Erro ao listar projetos: {e}")
        return []

def salvar_analise(projeto_id, tipo_analise, resumo_input, resultado_completo):
    """Salva o resultado de uma análise associada a um projeto específico."""
    if not projeto_id:
        logging.warning(f"Tentativa de salvar análise do tipo '{tipo_analise}' sem um projeto ativo. A análise não foi salva.")
        return

    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        c = conn.cursor()
        c.execute(
            "INSERT INTO analises (projeto_id, tipo_analise, resumo_input, resultado_completo) VALUES (?, ?, ?, ?)",
            (projeto_id, tipo_analise, resumo_input, resultado_completo)
        )
        conn.commit()
        conn.close()
        logging.info(f"Análise do tipo '{tipo_analise}' salva com sucesso para o projeto ID {projeto_id}.")
    except Exception as e:
        logging.error(f"Erro ao salvar análise para projeto ID {projeto_id}: {e}")

def carregar_analises_do_projeto(projeto_id):
    """Carrega todas as análises de um projeto específico para o Correlation Dashboard."""
    if not projeto_id:
        return []
        
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # Retorna os dados necessários para o dashboard
        c.execute("SELECT tipo_analise, resumo_input, resultado_completo FROM analises WHERE projeto_id = ? ORDER BY data_analise DESC", (projeto_id,))
        analises = c.fetchall()
        conn.close()
        return analises
    except Exception as e:
        logging.error(f"Erro ao carregar análises do projeto ID {projeto_id}: {e}")
        return []