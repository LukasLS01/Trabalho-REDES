import socket
import psutil
from criptografia import FerramentasCrypto

class ClienteTCP:
    def __init__(self, host, porta):
        self.host = host
        self.porta = porta
        self.key = b"0361231230000000"  # Mesma chave do servidor
        self.tool = FerramentasCrypto()

    def conectar(self):
        """Conecta ao servidor e entra em um loop para receber e processar comandos."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.host, self.porta))
                print(f"Conectado ao servidor em {self.host}:{self.porta}. Aguardando comandos...")
                
                while True:

                    iv = s.recv(16)
                    if not iv:
                        print("Servidor encerrou a conexão.")
                        break

                    dados_criptografados = s.recv(4096)
                    comando = self.tool.decrypt(iv, dados_criptografados, self.key)

                    if comando.lower() == "sair":
                        print("Comando 'sair' recebido. Desconectando...")
                        break
                    
                    
                    resposta = self.executar_comando(comando)
                    
     
                    resposta_iv, resposta_msg = self.tool.encrypt(resposta, self.key)
                    s.sendall(resposta_iv)
                    s.sendall(resposta_msg)

            except ConnectionRefusedError:
                print(f"Erro: Não foi possível conectar. Verifique se o servidor está rodando em {self.host}:{self.porta}")
            except ConnectionResetError:
                print("Erro: A conexão com o servidor foi perdida.")
            except Exception as e:
                print(f"Ocorreu um erro inesperado: {e}")

    def executar_comando(self, comando):
        """Executa comandos para obter informações do sistema local."""
        try:
            match comando.lower().strip():
                case "cpu":
                    qtdCPU = psutil.cpu_count(logical=False)
                    return f"Quantidade de núcleos físicos da CPU: {qtdCPU}"
                case "ram":
                    memoriaLivre = psutil.virtual_memory().available / (1024 ** 3)
                    return f"Quantidade de RAM livre: {memoriaLivre:.2f} GB"
                case "disco":
                    discoLivre = psutil.disk_usage('/').free / (1024 ** 3)
                    return f"Espaço em disco livre (partição principal): {discoLivre:.2f} GB"
                case "ip":
                    ips = "Lista dos IPs de cada Interface:\n"
                    for nic, addrs in psutil.net_if_addrs().items():
                        for addr in addrs:
                            if addr.family == socket.AF_INET:
                                ips += f"  {nic}: {addr.address}\n"
                                break
                    return ips.strip()
                case "interfaces_desativadas":
                    interfaces = ""
                    for nome, stats in psutil.net_if_stats().items():
                         if not stats.isup:
                              interfaces += f"  {nome}\n"
                    return f"Lista de interfaces desativadas:\n{interfaces if interfaces else 'Nenhuma'}"
                case "portas":
                    conexoes = psutil.net_connections()
                    portas_tcp = sorted({c.laddr.port for c in conexoes if c.status == 'LISTEN' and c.type == socket.SOCK_STREAM} ) 
                    return f"Portas TCP em escuta (LISTEN): {portas_tcp}"
                case _:
                    return "Comando não reconhecido pelo cliente."
        except Exception as e:
            return f"Erro ao executar comando no cliente: {e}"

if __name__ == "__main__":

    cliente = ClienteTCP('127.0.0.1', 1515)
    cliente.conectar()
