import socket
import threading
from criptografia import FerramentasCrypto

class ServidorTCP:
    def __init__(self, host, porta):
        self.key = b"0361231230000000"  
        self.host = host
        self.porta = porta
        self.servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tool = FerramentasCrypto()

        self.clientes = {}

        self.clientes_lock = threading.Lock()

    def iniciar_servidor(self):
        """Inicia o servidor e as threads para aceitar conexões e comandos."""
        self.servidor.bind((self.host, self.porta))
        self.servidor.listen()
        print(f"Servidor escutando em {self.host}:{self.porta}")


        thread_aceitar = threading.Thread(target=self.aceitar_conexoes, daemon=True)
        thread_aceitar.start()
        

        self.interface_comandos()

    def aceitar_conexoes(self):

        while True:
            try:
                cliente_socket, endereco = self.servidor.accept()
                print(f"\n[+] Nova conexão de: {endereco[0]}:{endereco[1]}")
                with self.clientes_lock:
                    self.clientes[endereco] = cliente_socket
            except Exception as e:
                print(f"[!] Erro ao aceitar conexões: {e}")
                break

    def remover_cliente(self, endereco):

        with self.clientes_lock:
            if endereco in self.clientes:
                self.clientes[endereco].close()
                del self.clientes[endereco]
                print(f"\n[-] Conexão com {endereco[0]}:{endereco[1]} removida.")

    def interface_comandos(self):
        """Interface para o administrador do servidor digitar comandos."""
        print("Digite 'help' para ver os comandos disponíveis.")
        while True:
            comando_input = input("Servidor> ").strip()
            if not comando_input:
                continue

            partes = comando_input.split(" ", 2)
            cmd_principal = partes[0].lower()

            match cmd_principal:
                case "help":
                    self.mostrar_ajuda()
                case "listar":
                    self.listar_clientes()
                case "exec":
                    self.executar_remoto(partes)
                case "sair":
                    print("Encerrando o servidor...")

                    with self.clientes_lock:
                        for endereco, sock in self.clientes.items():
                            try:
                                iv, msg_cript = self.tool.encrypt("sair", self.key)
                                sock.sendall(iv)
                                sock.sendall(msg_cript)
                                sock.close()
                            except:
                                pass 
                    self.servidor.close()
                    break
                case _:
                    print("Comando desconhecido. Digite 'help'.")
    
    def mostrar_ajuda(self):
        """Exibe a lista de comandos do servidor e os comandos que podem ser enviados aos clientes."""
        print("\n--- Comandos do Servidor ---")
        print("  listar         -> Lista todos os clientes conectados.")
        print("  exec <id> <cmd>-> Executa um comando em um cliente específico.")
        print("  sair           -> Encerra o servidor e desconecta todos os clientes.")
        print("  help           -> Mostra esta mensagem de ajuda.")
        print("\n--- Comandos para Executar no Cliente (via 'exec') ---")
        print("  cpu            -> Mostra a quantidade de núcleos físicos da CPU do cliente.")
        print("  ram            -> Mostra a quantidade de RAM livre do cliente.")
        print("  disco          -> Mostra o espaço em disco livre do cliente.")
        print("  ip             -> Lista os endereços IP do cliente.")
        print("  portas         -> Lista as portas TCP do cliente em modo de escuta.")
        print("  interfaces_desativadas -> Lista as interfaces de rede desativadas do cliente.")
        print("  sair           -> Desconecta o cliente do servidor.")

    def listar_clientes(self):
        """Exibe uma lista numerada dos clientes conectados."""
        with self.clientes_lock:
            if not self.clientes:
                print("Nenhum cliente conectado.")
                return
            print("Clientes conectados:")
            for i, endereco in enumerate(self.clientes.keys()):
                print(f"  {i+1}. {endereco[0]}:{endereco[1]}")

    def executar_remoto(self, partes):
        """Envia um comando para um cliente específico e recebe a resposta."""
        if len(partes) < 3:
            print("Uso: exec <id_cliente> <comando_para_executar>")
            return

        try:
            cliente_id = int(partes[1])
            comando_remoto = partes[2]

            with self.clientes_lock:

                lista_clientes = list(self.clientes.items())
                if not (1 <= cliente_id <= len(lista_clientes)):
                    print(f"Erro: ID de cliente inválido. Use 'listar' para ver os IDs.")
                    return
                
                endereco, cliente_socket = lista_clientes[cliente_id - 1]


            iv, dados_cript = self.tool.encrypt(comando_remoto, self.key)
            cliente_socket.sendall(iv)
            cliente_socket.sendall(dados_cript)

            if comando_remoto.lower() == "sair":
                print(f"Comando 'sair' enviado para {endereco[0]}:{endereco[1]}. O cliente será desconectado.")
                self.remover_cliente(endereco)
                return


            resposta_iv = cliente_socket.recv(16)
            if not resposta_iv:
                print(f"O cliente {endereco[0]}:{endereco[1]} parece ter desconectado.")
                self.remover_cliente(endereco)
                return

            resposta_cript = cliente_socket.recv(4096)
            resposta = self.tool.decrypt(resposta_iv, resposta_cript, self.key)
            
            print("="*20 + f"\nResposta de {endereco[0]}:{endereco[1]}:\n" + "="*20 + f"\n{resposta}\n")

        except (ValueError, IndexError):
            print("Erro: ID do cliente deve ser um número válido.")
        except Exception as e:
            print(f"Ocorreu um erro na comunicação com o cliente: {e}")

            if 'endereco' in locals():
                self.remover_cliente(endereco)

if __name__ == "__main__":
    servidor = ServidorTCP('0.0.0.0', 1515)
    servidor.iniciar_servidor()
