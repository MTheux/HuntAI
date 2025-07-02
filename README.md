# HuntIA - Sua Plataforma de Pentest Inteligente

![HuntIA Logo](https://raw.githubusercontent.com/SeuUsuario/SeuRepositorio/main/caminho/para/huntia_logo.png)
*(Substitua a URL da imagem pelo caminho real do seu logo no repositório)*
*(Se você tem o `huntbox_logo.png` na raiz do seu projeto local, pode ser `huntbox_logo.png`)*

## Visão Geral do Projeto

HuntIA é uma suíte de ferramentas inteligentes para testes de segurança (pentest), desenvolvida para automatizar e aprimorar diversas fases do processo de avaliação de vulnerabilidades. Utilizando o poder do Large Language Model (LLM) do Google Gemini, o HuntIA transforma a análise de segurança, a geração de relatórios e a orquestração de testes em tarefas mais eficientes e precisas.

Com o HuntIA, pentesters e analistas de segurança podem cortar significativamente o tempo gasto em tarefas repetitivas, focar na inteligência tática e gerar entregas de alta qualidade.

## Funcionalidades Principais

* **Contexto de Análise Global:** Adapte o comportamento do LLM com base em perfis de atacante (Novato, Experiente, APT) e cenários de ataque (Acesso Interno, Acesso Externo, Phishing, Red Team Exercise), tornando as análises mais contextuais e precisas.
* **OWASP Vulnerability Details:** Obtenha detalhes aprofundados sobre categorias e falhas específicas da OWASP Top 10.
* **Deep HTTP Insight:** Análise abrangente de requisições HTTP RAW, headers de resposta e configurações de servidor (Apache, Nginx, IIS) para identificar misconfigurations e vulnerabilidades.
* **OWASP Image Analyzer:** Analise diagramas, prints de tela ou trechos de código em imagens para identificar vulnerabilidades OWASP.
* **PoC Generator (HTML):** Gere Provas de Conceito (PoCs) em HTML para demonstrar vulnerabilidades web como CSRF, Clickjacking e XSS.
* **OpenAPI Analyzer:** Analise especificações de APIs (Swagger/OpenAPI) em busca de vulnerabilidades OWASP API Security Top 10 e falhas de design.
* **Static Code Analyzer (Avançado para JS/RAW):** Cole trechos de código ou conteúdo JavaScript (RAW/HTTP) para identificar vulnerabilidades e, principalmente, exposição de informações sensíveis (chaves de API, credenciais hardcoded, etc.).
* **Search Exploit:** Pesquise por exploits e shellcodes em seu repositório local do Exploit-DB, com análise aprofundada do LLM sobre o exploit selecionado.
* **Tactical Command Orchestrator:** Descreva um cenário de pentest e o LLM sugerirá comandos otimizados para ferramentas CLI específicas.
* **Pentest Playbook Generator:** Gere playbooks detalhados com fases, passos-chave, ferramentas e resultados esperados para diversos cenários de pentest.
* **Intelligent Pentest Validator:** Faça upload de evidências de pentest (prints, resultados) e o LLM avaliará a cobertura e a qualidade do seu teste, sugerindo melhorias.
* **Pentest Narrative Generator:** Gere narrativas de relatório de pentest completas e profissionais a partir de detalhes do cliente, aplicação e suas evidências de teste (incluindo imagens e outputs brutos de ferramentas). Ideal para compor relatórios de forma automatizada.
    * **Injeção de Conteúdo Dinâmico por Tipo de Pentest:** Adapta a narrativa com base se o pentest é Web, API, Infraestrutura ou Mobile.
    * **Narrativa para Testes de Resiliência:** Inclui descrições detalhadas de testes que **não** resultaram em falhas, comprovando a resiliência da aplicação.
    * **Integração com Outputs de Ferramentas:** O LLM processa outputs RAW de ferramentas (Burp, Acunetix, Invicti, Nmap, etc.) para detalhar os achados na narrativa.
* **Mobile Static Analyzer (Lightweight):** Realiza análise estática de segurança em aplicativos Android. Faça upload de um arquivo `.zip` contendo o APK descompilado (saída de `apktool -d` ou `jadx -d`) ou cole trechos de código (`AndroidManifest.xml`, Java/Smali/Kotlin) para identificar vulnerabilidades OWASP Mobile Top 10.

## Como Usar o HuntIA

### Pré-requisitos

* **Python 3.8+**
* **Git** (para clonar o repositório)
* **Java Development Kit (JDK)** (para descompilação de APKs com Jadx/APKTool, se for fazer localmente antes de zipar)
* **Chave de API Google Gemini:** Obtenha uma em [Google AI Studio](https://aistudio.google.com/app/apikey).
* **(Opcional) Chaves de API para serviços externos:**
    * **NVD API Key:** Para consultar a Base Nacional de Vulnerabilidades (NIST).
    * **Netlas API Key:** Para funcionalidades de reconhecimento passivo (se houver integrações futuras que a utilizem).

### Instalação

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/SeuUsuario/SeuRepositorio.git](https://github.com/SeuUsuario/SeuRepositorio.git)
    cd SeuRepositorio
    ```
    *(Lembre-se de substituir `SeuUsuario/SeuRepositorio` pelo seu usuário e nome real do repositório no GitHub)*

2.  **Crie um ambiente virtual (recomendado):**
    ```bash
    python -m venv venv
    .\venv\Scripts\activate   # No Windows
    source venv/bin/activate  # No Linux/macOS
    ```

3.  **Instale as dependências:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Você pode precisar criar um `requirements.txt` primeiro, listando as libs: `streamlit`, `python-dotenv`, `google-generativeai`, `Pillow`, `requests`, `PyYAML`, `pandas`, `streamlit-option-menu`, `shlex`, `zipfile`)*

4.  **Configure suas chaves de API:**
    * Crie um arquivo chamado `.env` na raiz do seu projeto (na mesma pasta do `HuntIA.py`).
    * Adicione suas chaves de API neste arquivo:
        ```
        GOOGLE_API_KEY=SUA_CHAVE_GEMINI_AQUI
        NVD_API_KEY=SUA_CHAVE_NVD_AQUI
        NETLAS_API_KEY=SUA_CHAVE_NETLAS_AQUI
        ```

5.  **Configure o Tema e Favicon (Opcional):**
    * Crie uma pasta chamada `.streamlit` na raiz do seu projeto.
    * Dentro de `.streamlit`, crie um arquivo chamado `config.toml`.
    * Cole o seguinte conteúdo para o tema preto e vermelho:
        ```toml
        # .streamlit/config.toml
        [theme]
        primaryColor="#E50000"        # Vermelho vibrante
        backgroundColor="#000000"    # Fundo principal preto
        secondaryBackgroundColor="#1A1A1A" # Fundo secundário (sidebar, blocos)
        textColor="#FAFAFA"          # Cor do texto (branco suave)
        font="monospace"             # Fonte monoespaçada

        [global]
        disableWatchdogWarning=true
        ```
    * Para o favicon, se tiver uma imagem (ex: `huntbox_logo.png` na raiz do projeto), configure no `HuntIA.py`:
        ```python
        # No seu HuntIA.py, linha ~22 (set_page_config)
        st.set_page_config(
            layout="wide",
            page_title="HuntIA - Pentest Suite",
            page_icon="huntbox_logo.png" # Ou o caminho do seu arquivo de ícone
        )
        ```

### Execução

Para iniciar o aplicativo HuntIA, execute o seguinte comando no terminal (na raiz do seu projeto):

```bash
streamlit run HuntIA.py