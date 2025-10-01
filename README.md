📊 FuçaRede - Sistema Avançado de Análise de Tráfego de Rede

Bem-vindo ao FucaRede!
Este projeto é uma ferramenta poderosa para análise e monitoramento de pacotes de rede, desenvolvida em Python.
Com ele, você pode capturar, analisar e registrar o tráfego de rede da sua máquina de forma simples e eficiente.

📁 Pré-requisitos

Antes de executar o projeto, verifique se você possui os seguintes itens instalados no seu sistema:

🐍 Python 3.8+ – Linguagem utilizada no projeto
📦 pip – Gerenciador de pacotes do Python
📡 tcpdump – Ferramenta de captura de pacotes de rede

🐧 Instalação no Linux

Atualize os pacotes do sistema:
sudo apt update && sudo apt upgrade -y

Instale o Python e pip (caso não tenha):
sudo apt install python3 python3-pip -y

Instale o tcpdump:
sudo apt install tcpdump -y


Clone o repositório e entre na pasta do projeto:
git clone https://github.com/usuario/fucarede.git
cd fucarede


Execute o programa:
sudo python3 fucarede.py

🪟 Instalação no Windows

Baixe e instale o Python:
👉 https://www.python.org/downloads/

Durante a instalação, marque a opção "Add Python to PATH".

Baixe o tcpdump para Windows:
Você pode usar o WinDump (versão compatível):
👉 https://www.winpcap.org/windump/

Clone o repositório ou baixe o código ZIP:
Via Git Bash:

git clone https://github.com/usuario/fucarede.git
cd fucarede

Ou extraia o arquivo ZIP e entre na pasta pelo terminal.

Execute o projeto:
python fucarede.py

🍏 Instalação no macOS

Instale o Homebrew (se ainda não tiver):
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"


Instale o Python e tcpdump:
brew install python3 tcpdump


Clone o repositório e entre no diretório:
git clone https://github.com/usuario/fucarede.git
cd fucarede


Execute o projeto:
sudo python3 fucarede.py

⚙️ Executando pelo VS Code (opcional)

Instale o Visual Studio Code
Abra a pasta do projeto pelo VS Code
Instale a extensão Python

No terminal integrado, execute:
sudo python3 fucarede.py   # (Linux/macOS)
python fucarede.py         # (Windows)

🧪 Exemplo de uso
sudo python3 fucarede.py
A saída mostrará o tráfego de rede capturado em tempo real. Você também pode configurar filtros dentro do código para capturar apenas protocolos específicos (como HTTP, DNS, etc.).

📄 Licença
Sinta-se à vontade para usar, modificar e compartilhar.
