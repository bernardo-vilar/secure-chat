import socket
import threading
import json
import time

ACTIVE_USERS = {}
USERS = {"alice": "1234", "bob": "abcd"} 

COORD_PORT = 8888

def handle_client(conn, addr):
    print(f"Nova conexão de {addr}")
    username = None 
    
    try:
        data = conn.recv(1024).decode()
        parts = data.split("|")
        
        if len(parts) != 4 or parts[0] != "LOGIN": 
            conn.send(b"FAIL|Protocolo invalido.")
            return
            
        command, username, password, p2p_port_str = parts 
        
        if username in USERS and USERS[username] == password:
            conn.send(b"OK|Login bem-sucedido.")
            print(f"usuário {username} logado.")
            
            p2p_port = int(p2p_port_str)
            ACTIVE_USERS[username] = (addr[0], p2p_port) 
            
            while True:
                conn.settimeout(30)
                try:
                    data = conn.recv(1024).decode()
                    if not data: 
                        break 
                    
                    if data == "GET_LIST":
                        user_list = [user for user in ACTIVE_USERS if user != username]
                        conn.send(f"LIST|{json.dumps(user_list)}".encode())
                    
                    elif data == "QUIT":
                        break 
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Erro de comunicação com {username}: {e}")
                    break

        else:
            conn.send(b"FAIL|Credenciais invalidas.")
            print(f"Tentativa de login falhou para {username}.")
            
    except Exception as e:
        print(f"Erro no servidor com {addr}: {e}")
        
    finally:
        if username and username in ACTIVE_USERS:
            del ACTIVE_USERS[username]
            print(f"Usuário {username} desconectado da coordenação.")
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', COORD_PORT)) 
    server.listen(5)
    print(f"Servidor de Coordenação online na porta {COORD_PORT}.")
    
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        except KeyboardInterrupt:
            print("Servidor encerrado.")
            break

if __name__ == "__main__":
    start_server()