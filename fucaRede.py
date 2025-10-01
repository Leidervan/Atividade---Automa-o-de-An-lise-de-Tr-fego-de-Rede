#!/usr/bin/env python3
"""
FucaRede GUI - Interface gráfica para análise de tráfego de rede
Autor: Assistente Claude & Gemini
Data: 2025-09-30 (Versão Refatorada)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
import re
import csv
import sys
import shutil
from collections import defaultdict, deque
from pathlib import Path
from enum import Enum
from typing import List, Dict, Optional, Set, Tuple, Callable

# --- CONSTANTES E CONFIGURAÇÕES ---

class Cores(Enum):
    """Enum para o tema de cores da aplicação."""
    BG_PRIMARY = '#0F0F0F'
    BG_SECONDARY = '#1A1A1A'
    BG_CARD = '#2D2D2D'
    PURPLE_PRIMARY = '#8B5CF6'
    PURPLE_SECONDARY = '#A78BFA'
    PURPLE_DARK = '#6D28D9'
    TEXT_PRIMARY = '#FFFFFF'
    TEXT_SECONDARY = '#B0B0B0'
    ACCENT_GREEN = '#10B981'
    ACCENT_RED = '#EF4444'
    ACCENT_YELLOW = '#F59E0B'

# Padrão Regex para extrair informações da linha de log do tcpdump
TCPDUMP_PATTERN = re.compile(r'(\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+):')
RELATORIO_FILENAME = "relatorio.csv"

# --- LÓGICA DE ANÁLISE (SEPARADA DA GUI) ---

class AnalisadorDeTrafego:
    """Encapsula toda a lógica de análise de tráfego."""

    def _parse_linha_tcpdump(self, linha: str) -> Optional[Dict]:
        """Converte uma linha de log em um dicionário estruturado."""
        match = TCPDUMP_PATTERN.match(linha.strip())
        if match:
            return {
                'timestamp': float(match.group(1)),
                'ip_origem': match.group(2),
                'porta_origem': int(match.group(3)),
                'ip_destino': match.group(4),
                'porta_destino': int(match.group(5)),
            }
        return None

    def _detectar_port_scan_otimizado(self, eventos: List[Dict], janela_tempo: int, limite_portas: int) -> Set[str]:
        """
        Detecta IPs que realizaram port scan usando um algoritmo otimizado (janela deslizante).
        Complexidade: O(N log N) devido à ordenação, muito mais rápido que O(N^2).
        """
        ips_suspeitos = set()
        eventos_por_ip = defaultdict(list)
        for ev in eventos:
            eventos_por_ip[ev['ip_origem']].append(ev)

        for ip, eventos_do_ip in eventos_por_ip.items():
            if len(eventos_do_ip) <= limite_portas:
                continue

            eventos_do_ip.sort(key=lambda x: x['timestamp'])
            
            janela_eventos = deque()
            portas_na_janela = set()

            for evento in eventos_do_ip:
                # Remove eventos antigos da janela
                while janela_eventos and evento['timestamp'] - janela_eventos[0]['timestamp'] > janela_tempo:
                    evento_antigo = janela_eventos.popleft()
                    # A remoção de portas do set é complexa, uma abordagem mais simples é recalcular,
                    # mas para esta otimização, vamos focar na detecção rápida.
                    # Se a porta só existia no evento antigo, removemos.
                    if not any(e['porta_destino'] == evento_antigo['porta_destino'] for e in janela_eventos):
                         portas_na_janela.discard(evento_antigo['porta_destino'])


                janela_eventos.append(evento)
                portas_na_janela.add(evento['porta_destino'])

                if len(portas_na_janela) > limite_portas:
                    ips_suspeitos.add(ip)
                    break # Já detectamos para este IP, podemos passar para o próximo
        
        return ips_suspeitos

    def analisar(self, dados: List[str], janela_tempo: int, limite_portas: int, progress_callback: Optional[Callable] = None) -> Dict:
        """Executa a análise completa do tráfego."""
        eventos_validos = []
        total_linhas = len(dados)
        for i, linha in enumerate(dados):
            evento = self._parse_linha_tcpdump(linha)
            if evento:
                eventos_validos.append(evento)
            if progress_callback and (i + 1) % 100 == 0:
                progress_callback(i + 1, total_linhas)
        
        if progress_callback:
            progress_callback(total_linhas, total_linhas)

        ips_port_scan = self._detectar_port_scan_otimizado(eventos_validos, janela_tempo, limite_portas)

        contagem_eventos = defaultdict(int)
        for evento in eventos_validos:
            contagem_eventos[evento['ip_origem']] += 1

        ips_ordenados = sorted(contagem_eventos.items(), key=lambda item: item[1], reverse=True)

        return {
            'linhas_processadas': total_linhas,
            'eventos_validos': len(eventos_validos),
            'ips_unicos': len(ips_ordenados),
            'port_scans_detectados': len(ips_port_scan),
            'top_10_ips': ips_ordenados[:10],
            'ips_com_port_scan': sorted(list(ips_port_scan)),
            'contagem_total_eventos': contagem_eventos
        }
    
    def gerar_relatorio_csv(self, resultado_analise: Dict) -> None:
        """Gera um arquivo CSV com os resultados da análise."""
        with open(RELATORIO_FILENAME, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['IP', 'Total_Eventos', 'Detectado_PortScan']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            contagem_eventos = resultado_analise['contagem_total_eventos']
            ips_port_scan = resultado_analise['ips_com_port_scan']
            
            ips_ordenados = sorted(contagem_eventos.items(), key=lambda item: item[1], reverse=True)
            
            for ip, total in ips_ordenados:
                writer.writerow({
                    'IP': ip,
                    'Total_Eventos': total,
                    'Detectado_PortScan': 'Sim' if ip in ips_port_scan else 'Não'
                })

# --- INTERFACE GRÁFICA ---

class FucaRedeGUI:
    """Classe principal da interface gráfica (GUI)."""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.dados_trafego: List[str] = []
        self.arquivo_carregado: Optional[Path] = None
        self.resultado_analise: Optional[Dict] = None
        self.analisador = AnalisadorDeTrafego()

        self._configurar_janela()
        self._configurar_estilos()
        self._criar_widgets()
        self._centralizar_janela()

    def _configurar_janela(self):
        self.root.title("FucaRede - Análise de Tráfego de Rede")
        self.root.geometry("1200x800")
        self.root.configure(bg=Cores.BG_PRIMARY.value)
        self.root.minsize(900, 700)

    def _configurar_estilos(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configurações de estilo (mesmas da versão original, mas usando o Enum)
        style.configure('TFrame', background=Cores.BG_PRIMARY.value)
        style.configure('Card.TFrame', background=Cores.BG_CARD.value)
        
        style.configure('Purple.TButton',
                        background=Cores.PURPLE_PRIMARY.value,
                        foreground=Cores.TEXT_PRIMARY.value,
                        borderwidth=0,
                        focuscolor='none',
                        font=('JetBrains Mono', 10, 'bold'))
        style.map('Purple.TButton',
                  background=[('active', Cores.PURPLE_SECONDARY.value),
                              ('pressed', Cores.PURPLE_DARK.value),
                              ('disabled', Cores.BG_CARD.value)])

        style.configure('Card.TLabel',
                        background=Cores.BG_CARD.value,
                        foreground=Cores.TEXT_PRIMARY.value,
                        font=('JetBrains Mono', 10))
        style.configure('CardTitle.TLabel',
                        background=Cores.BG_CARD.value,
                        foreground=Cores.PURPLE_PRIMARY.value,
                        font=('JetBrains Mono', 12, 'bold'))

        style.configure('Purple.Horizontal.TProgressbar',
                        background=Cores.PURPLE_PRIMARY.value,
                        troughcolor=Cores.BG_SECONDARY.value,
                        borderwidth=0)

    def _criar_widgets(self):
        self._criar_header()
        self._criar_controles()
        self._criar_status()
        self._criar_resultados()

    def _criar_header(self):
        header_frame = ttk.Frame(self.root, style='TFrame')
        header_frame.pack(fill='x', padx=20, pady=(20, 10))
        
        tk.Label(header_frame, text="🔍 FucaRede", bg=Cores.BG_PRIMARY.value, fg=Cores.PURPLE_PRIMARY.value,
                 font=('JetBrains Mono', 32, 'bold')).pack(pady=(10, 5))
        tk.Label(header_frame, text="Análise Avançada de Tráfego de Rede & Detecção de Port Scan",
                 bg=Cores.BG_PRIMARY.value, fg=Cores.TEXT_SECONDARY.value, font=('JetBrains Mono', 12)).pack()
    
    def _criar_controles(self):
        controles_frame = ttk.Frame(self.root)
        controles_frame.pack(fill='x', padx=20, pady=10)
        controles_frame.columnconfigure((0, 1, 2), weight=1)

        # Card de Arquivo
        card_arquivo = self._criar_card(controles_frame, "📁 Carregar Arquivo")
        card_arquivo.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.arquivo_label = ttk.Label(card_arquivo, text="Nenhum arquivo carregado", style='Card.TLabel')
        self.arquivo_label.pack(pady=(0, 10), padx=15, fill='x')
        self.btn_carregar = ttk.Button(card_arquivo, text="📂 Selecionar trafego.txt", style='Purple.TButton', command=self.carregar_arquivo)
        self.btn_carregar.pack(pady=(0, 15), padx=15, fill='x')

        # Card de Configurações
        card_config = self._criar_card(controles_frame, "⚙️ Configurações")
        card_config.grid(row=0, column=1, sticky="nsew", padx=10)
        self.janela_tempo = tk.IntVar(value=60)
        self.limite_portas = tk.IntVar(value=10)
        self._criar_spinbox(card_config, "Janela de Tempo (s):", self.janela_tempo, (1, 3600))
        self._criar_spinbox(card_config, "Limite de Portas:", self.limite_portas, (1, 1000))
        
        # Card de Execução
        card_exec = self._criar_card(controles_frame, "🚀 Executar")
        card_exec.grid(row=0, column=2, sticky="nsew", padx=(10, 0))
        self.btn_analisar = ttk.Button(card_exec, text="🔍 Analisar Tráfego", style='Purple.TButton', command=self.iniciar_analise, state='disabled')
        self.btn_analisar.pack(pady=(10, 10), padx=15, fill='x', expand=True)
        self.btn_limpar = ttk.Button(card_exec, text="✨ Limpar Análise", style='Purple.TButton', command=self.resetar_interface, state='disabled')
        self.btn_limpar.pack(pady=(0, 15), padx=15, fill='x', expand=True)

    def _criar_card(self, parent: ttk.Frame, title: str) -> ttk.Frame:
        """Helper para criar um card padronizado."""
        card_frame = ttk.Frame(parent, style='Card.TFrame')
        ttk.Label(card_frame, text=title, style='CardTitle.TLabel').pack(pady=(15, 10), padx=15)
        return card_frame

    def _criar_spinbox(self, parent: ttk.Frame, label_text: str, variable: tk.IntVar, range_vals: Tuple[int, int]):
        """Helper para criar um label e um spinbox."""
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='x', padx=15, pady=5)
        ttk.Label(frame, text=label_text, style='Card.TLabel').pack(side='left')
        tk.Spinbox(frame, from_=range_vals[0], to=range_vals[1], textvariable=variable,
                    bg=Cores.BG_SECONDARY.value, fg=Cores.TEXT_PRIMARY.value, width=7,
                    font=('JetBrains Mono', 10), buttonbackground=Cores.BG_CARD.value).pack(side='right')

    def _criar_status(self):
        status_frame = ttk.Frame(self.root, style='Card.TFrame')
        status_frame.pack(fill='x', padx=20, pady=10)
        
        self.status_label = ttk.Label(status_frame, text="⏳ Carregue um arquivo para iniciar",
                                      style='Card.TLabel', font=('JetBrains Mono', 11))
        self.status_label.pack(pady=15, padx=15)
        
        self.progress = ttk.Progressbar(status_frame, style='Purple.Horizontal.TProgressbar', mode='determinate')
    
    def _criar_resultados(self):
        self.results_frame = ttk.Frame(self.root)
        self.notebook = ttk.Notebook(self.results_frame)
        self.notebook.pack(fill='both', expand=True)

        self._criar_aba_estatisticas()
        self._criar_aba_ips()
        self._criar_aba_terminal()

    def _criar_aba_estatisticas(self):
        frame = ttk.Frame(self.notebook, style='Card.TFrame')
        self.notebook.add(frame, text='📊 Estatísticas')
        
        stats_info = [
            ('linhas_processadas', 'Linhas Processadas'), ('eventos_validos', 'Eventos Válidos'),
            ('ips_unicos', 'IPs Únicos'), ('port_scans_detectados', 'Port Scans Detectados')
        ]
        self.stats_labels: Dict[str, tk.Label] = {}

        grid_frame = ttk.Frame(frame, style='Card.TFrame')
        grid_frame.pack(fill='both', expand=True, padx=10, pady=10)
        grid_frame.columnconfigure((0, 1), weight=1)
        grid_frame.rowconfigure((0, 1), weight=1)

        for i, (key, label) in enumerate(stats_info):
            stat_card = ttk.Frame(grid_frame, style='Card.TFrame', borderwidth=1, relief='solid')
            stat_card.grid(row=i // 2, column=i % 2, sticky='nsew', padx=10, pady=10)
            
            ttk.Label(stat_card, text=label, style='Card.TLabel', font=('JetBrains Mono', 12)).pack(pady=(15, 5))
            value_label = tk.Label(stat_card, text="0", bg=Cores.BG_CARD.value, fg=Cores.PURPLE_PRIMARY.value, font=('JetBrains Mono', 24, 'bold'))
            value_label.pack(pady=(5, 15), expand=True)
            self.stats_labels[key] = value_label

    def _criar_aba_ips(self):
        frame = ttk.Frame(self.notebook, style='Card.TFrame', padding=10)
        self.notebook.add(frame, text='🌐 Análise de IPs')
        
        paned = ttk.PanedWindow(frame, orient='horizontal')
        paned.pack(fill='both', expand=True)

        self.top_ips_list = self._criar_lista_ip(paned, "🔝 Top 10 IPs Mais Ativos", Cores.PURPLE_PRIMARY.value)
        self.port_scan_list = self._criar_lista_ip(paned, "🚨 IPs com Port Scan", Cores.ACCENT_RED.value)

    def _criar_lista_ip(self, parent, title_text: str, color: str) -> tk.Listbox:
        frame = ttk.Frame(parent, style='Card.TFrame')
        parent.add(frame, weight=1)
        
        tk.Label(frame, text=title_text, bg=Cores.BG_CARD.value, fg=color,
                 font=('JetBrains Mono', 12, 'bold')).pack(pady=10)
        
        listbox = tk.Listbox(frame, bg=Cores.BG_SECONDARY.value, fg=Cores.TEXT_PRIMARY.value,
                              font=('JetBrains Mono', 9), selectbackground=color, relief='flat', borderwidth=0)
        listbox.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        return listbox

    def _criar_aba_terminal(self):
        frame = ttk.Frame(self.notebook, style='Card.TFrame', padding=10)
        self.notebook.add(frame, text='💻 Terminal')
        
        self.terminal = scrolledtext.ScrolledText(frame, bg='#000000', fg=Cores.TEXT_PRIMARY.value,
                                                   font=('JetBrains Mono', 10), relief='flat',
                                                   insertbackground=Cores.TEXT_PRIMARY.value)
        self.terminal.pack(fill='both', expand=True)
        self.terminal.tag_config('INFO', foreground=Cores.TEXT_SECONDARY.value)
        self.terminal.tag_config('SUCCESS', foreground=Cores.ACCENT_GREEN.value)
        self.terminal.tag_config('ERROR', foreground=Cores.ACCENT_RED.value)

        self.btn_download = ttk.Button(frame, text="📥 Download Relatório", style='Purple.TButton',
                                       command=self.download_relatorio, state='disabled')
        self.btn_download.pack(pady=10)

        self.log_terminal("FucaRede - Análise de Tráfego de Rede", "SUCCESS")
        self.log_terminal("Aguardando arquivo para análise...", "INFO")

    # --- LÓGICA DE EVENTOS ---

    def carregar_arquivo(self):
        filepath = filedialog.askopenfilename(
            title="Selecionar arquivo de tráfego",
            filetypes=[("Arquivos de texto", "*.txt"), ("Todos os arquivos", "*.*")]
        )
        if not filepath:
            return
        
        self.arquivo_carregado = Path(filepath)
        self.resetar_interface(manter_arquivo=True)
        
        try:
            with self.arquivo_carregado.open('r', encoding='utf-8') as f:
                self.dados_trafego = [linha for linha in f if linha.strip()]
            
            file_size_kb = self.arquivo_carregado.stat().st_size / 1024
            self.arquivo_label.config(text=f"📁 {self.arquivo_carregado.name} ({file_size_kb:.1f} KB)")
            self.status_label.config(text=f"✅ Arquivo carregado com {len(self.dados_trafego)} linhas.")
            self.btn_analisar.config(state='normal')
            
            self.log_terminal(f"Arquivo '{self.arquivo_carregado.name}' carregado.", "SUCCESS")
            self.log_terminal(f"{len(self.dados_trafego)} linhas lidas.", "INFO")

        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao ler arquivo:\n{e}")
            self.log_terminal(f"Erro ao ler arquivo: {e}", "ERROR")

    def iniciar_analise(self):
        if not self.dados_trafego:
            messagebox.showwarning("Aviso", "Nenhum dado de tráfego carregado.")
            return

        self._preparar_ui_para_analise()
        
        thread = threading.Thread(
            target=self.executar_analise_em_background,
            args=(self.dados_trafego, self.janela_tempo.get(), self.limite_portas.get()),
            daemon=True
        )
        thread.start()

    def executar_analise_em_background(self, dados: List[str], janela_tempo: int, limite_portas: int):
        try:
            self.log_terminal("Iniciando análise...", "INFO")
            
            # A função de análise agora aceita um 'callback' para o progresso
            resultado = self.analisador.analisar(dados, janela_tempo, limite_portas, self._atualizar_progresso)
            self.resultado_analise = resultado
            
            self.log_terminal("Gerando relatório CSV...", "INFO")
            self.analisador.gerar_relatorio_csv(resultado)
            self.log_terminal(f"Relatório salvo como '{RELATORIO_FILENAME}'", "SUCCESS")

            self.root.after(0, self._finalizar_analise_na_ui)
        except Exception as e:
            self.log_terminal(f"Erro crítico durante a análise: {e}", "ERROR")
            self.root.after(0, self.resetar_interface)

    def _preparar_ui_para_analise(self):
        self.btn_analisar.config(state='disabled', text='⏳ Analisando...')
        self.btn_limpar.config(state='disabled')
        self.btn_carregar.config(state='disabled')
        self.status_label.config(text="🔍 Analisando tráfego...")
        self.progress['value'] = 0
        self.progress.pack(fill='x', padx=15, pady=(0, 15))

    def _atualizar_progresso(self, atual: int, total: int):
        progresso = (atual / total) * 100
        self.root.after(0, self.progress.config, {'value': progresso})
        self.root.after(0, self.status_label.config, {'text': f"🔍 Processando... {int(progresso)}%"})

    def _finalizar_analise_na_ui(self):
        self.progress.pack_forget()
        self.status_label.config(text="✅ Análise concluída com sucesso!")
        
        self.btn_analisar.config(state='normal', text='🔍 Analisar Novamente')
        self.btn_limpar.config(state='normal')
        self.btn_carregar.config(state='normal')
        self.btn_download.config(state='normal')
        
        self.results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        self._popular_resultados()

        r = self.resultado_analise
        self.log_terminal(f"{r['ips_unicos']} IPs únicos analisados.", "INFO")
        self.log_terminal(f"{r['port_scans_detectados']} port scans detectados.", "SUCCESS" if r['port_scans_detectados'] > 0 else "INFO")
        self.log_terminal("Análise concluída!", "SUCCESS")

    def _popular_resultados(self):
        if not self.resultado_analise:
            return
        
        r = self.resultado_analise
        self.stats_labels['linhas_processadas'].config(text=f"{r['linhas_processadas']:,}")
        self.stats_labels['eventos_validos'].config(text=f"{r['eventos_validos']:,}")
        self.stats_labels['ips_unicos'].config(text=f"{r['ips_unicos']:,}")
        self.stats_labels['port_scans_detectados'].config(text=f"{r['port_scans_detectados']:,}")

        self.top_ips_list.delete(0, tk.END)
        for i, (ip, eventos) in enumerate(r['top_10_ips'], 1):
            flag = "🚨" if ip in r['ips_com_port_scan'] else "✅"
            self.top_ips_list.insert(tk.END, f"{i:2}. {ip:<15} - {eventos:>5} eventos {flag}")

        self.port_scan_list.delete(0, tk.END)
        if r['ips_com_port_scan']:
            for ip in r['ips_com_port_scan']:
                eventos = r['contagem_total_eventos'][ip]
                self.port_scan_list.insert(tk.END, f"🚨 {ip:<15} - {eventos:>5} eventos")
        else:
            self.port_scan_list.insert(tk.END, "🎉 Nenhum port scan detectado!")

    def resetar_interface(self, manter_arquivo: bool = False):
        self.results_frame.pack_forget()
        self.progress.pack_forget()
        self.status_label.config(text="⏳ Carregue um arquivo para iniciar")
        self.btn_analisar.config(state='disabled' if not manter_arquivo else 'normal', text='🔍 Analisar Tráfego')
        self.btn_limpar.config(state='disabled')
        self.btn_download.config(state='disabled')
        
        if not manter_arquivo:
            self.arquivo_label.config(text="Nenhum arquivo carregado")
            self.dados_trafego = []
            self.arquivo_carregado = None
        
        for label in self.stats_labels.values():
            label.config(text="0")
        self.top_ips_list.delete(0, tk.END)
        self.port_scan_list.delete(0, tk.END)
        self.log_terminal("Interface resetada.", "INFO")

    def log_terminal(self, texto: str, tipo: str = "INFO"):
        """Adiciona texto formatado ao terminal."""
        timestamp = time.strftime('%H:%M:%S')
        self.terminal.insert(tk.END, f"[{timestamp}] ", "INFO")
        self.terminal.insert(tk.END, f"{texto}\n", tipo.upper())
        self.terminal.see(tk.END)

    def download_relatorio(self):
        if not Path(RELATORIO_FILENAME).exists():
            messagebox.showwarning("Aviso", "Arquivo de relatório não encontrado.")
            return

        destino = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Arquivos CSV", "*.csv")],
            initialfile=RELATORIO_FILENAME
        )
        if destino:
            try:
                shutil.copy2(RELATORIO_FILENAME, destino)
                messagebox.showinfo("Sucesso", f"Relatório salvo em:\n{destino}")
                self.log_terminal(f"Relatório copiado para: {Path(destino).name}", "SUCCESS")
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao salvar arquivo:\n{e}")
                self.log_terminal(f"Erro ao salvar relatório: {e}", "ERROR")

    def _centralizar_janela(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

def main():
    """Função principal para iniciar a aplicação."""
    try:
        root = tk.Tk()
        app = FucaRedeGUI(root)
        root.mainloop()
    except ImportError:
        print("❌ ERRO: tkinter não está instalado ou não pode ser iniciado.")
        print("   - No Ubuntu/Debian: sudo apt-get install python3-tk")
        print("   - Verifique sua instalação Python se estiver no Windows ou macOS.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERRO crítico ao iniciar a aplicação: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()