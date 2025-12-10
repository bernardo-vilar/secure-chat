import socket
import ssl
import threading
import hmac
import hashlib
import json
import os
import sys
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

USERS = {"alice": "1234", "bob": "abcd"} 
SECRET_KEY = None 
ECDH_CURVE = ec.SECP384R1()

P2P_IS_CONNECTED = threading.Event()
P2P_CLIENT_SOCKET = None 

P2P_PORT = 9999 
COORD_IP = '127.0.0.1' 
COORD_PORT = 8888 


def hmac_password(username, password):
    return hmac.new(username.encode(), password.encode(), hashlib.sha256).hexdigest()

def receive_full_pem(sock):
    buffer = b""
    terminator = b"-----END PUBLIC KEY-----" 
    sock.settimeout(5.0) 
    
    while terminator not in buffer:
        try:
            chunk = sock.recv(1024)
            if not chunk:
                return None
            buffer += chunk
        except socket.timeout:
            return None
        except ssl.SSLError as e:
            print(f"erro SSL durante o recebimento de PEM: {e}")
            return None
    
    return buffer

def perform_key_exchange(sock, is_initiator):
    global SECRET_KEY

    my_private_key = ec.generate_private_key(ECDH_CURVE, default_backend()) 
    my_public_key = my_private_key.public_key()
    
    my_public_bytes = my_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    if is_initiator:
        sock.sendall(my_public_bytes)
        peer_public_bytes = receive_full_pem(sock)
    else:
        peer_public_bytes = receive_full_pem(sock)
        sock.sendall(my_public_bytes)

    if not peer_public_bytes:
        print("falha na recepção da chave pública do peer.")
        return False
        
    try:
        peer_public_key = serialization.load_pem_public_key(
            peer_public_bytes,
            backend=default_backend()
        )
        if not isinstance(peer_public_key, EllipticCurvePublicKey):
            print("chave pública recebida não é uma chave de curva elíptica.")
            return False
            
    except Exception as e:
        print(f"erro ao carregar chave pública do peer: {e}")
        return False

    shared_key = my_private_key.exchange(ec.ECDH(), peer_public_key)
    SECRET_KEY = hashlib.sha256(shared_key).digest()

    sock.settimeout(None)
    
    print("troca ECDH concluída! chave secreta compartilhada estabelecida.")
    return True

def authenticate_peer(sock, my_user, my_pass, is_initiator):    
    try:
        peer_cert = sock.getpeercert()
        if not peer_cert:
            print("falha na Autenticação (mTLS): Nenhuma informação de certificado do peer.")
            return False

        peer_cn_info = [i[0][1] for i in peer_cert['subject'] if i[0][0] == 'commonName']
        peer_user_cert = peer_cn_info[0] if peer_cn_info else None

        if peer_user_cert not in USERS:
            print(f" falha: Usuário do certificado ({peer_user_cert}) desconhecido no sistema.")
            return False

        print(f" Processo autenticado via mTLS. Usuário esperado: **{peer_user_cert}**.")

    except Exception as e:
        print(f" Erro Crítico na Autenticação (Certificado): {e}")
        return False
        
    my_hmac = hmac_password(my_user, my_pass)
    
    if is_initiator:
        sock.send(f"{my_user}|{my_hmac}".encode())
        data = sock.recv(1024).decode()
    else:
        data = sock.recv(1024).decode()
        sock.send(f"{my_user}|{my_hmac}".encode())

    try:
        peer_login_user, peer_login_hmac = data.split("|")
        
        if peer_login_user != peer_user_cert:
            print(f" falha de Autentidade: Login ({peer_login_user}) não corresponde ao certificado ({peer_user_cert}).")
            sock.send(b"FAIL_CN_MISMATCH")
            return False

        expected_hmac = hmac_password(peer_user_cert, USERS.get(peer_user_cert, ""))
        
        if hmac.compare_digest(peer_login_hmac, expected_hmac):
            sock.send(b"OK")
            print(f"usuário **{peer_user_cert}** autenticado com sucesso (Login/HMAC).")
        else:
            sock.send(b"FAIL_HMAC")
            print(f"falha na Autenticação do Usuário: Senha inválida para {peer_user_cert}")
            return False
            
    except Exception as e:
        print(" erro no protocolo de Login:", e)
        return False

    if is_initiator:
        resp = sock.recv(1024).decode()
        if resp != "OK":
            print(f"O peer respondeu com falha final: {resp}")
            return False
        
    return True
    
def send_messages(sock):
    """Envia mensagens com HMAC para garantir integridade."""
    global SECRET_KEY
    if not SECRET_KEY:
        return
        
    while True:
        try:
            msg = input()
            digest = hmac.new(SECRET_KEY, msg.encode(), hashlib.sha256).hexdigest()
            sock.send(f"{msg}|{digest}".encode())
            print("You:", msg)
        except Exception:
            pass

def receive_messages(sock):
    """Recebe mensagens e verifica HMAC para garantir integridade, com tratamento de erros."""
    global SECRET_KEY
    if not SECRET_KEY:
        return

    while True:
        try:
            data = sock.recv(1024).decode()
            if not data:
                print("Conexão P2P fechada pelo peer.")
                break
            
            try:
                msg, digest = data.rsplit("|", 1)
            except ValueError:
            
                print("erro de protocolo: Mensagem incompleta ou malformada recebida. Descartando pacote.")
                continue 
                
            
            expected = hmac.new(SECRET_KEY, msg.encode(), hashlib.sha256).hexdigest()
            
            if hmac.compare_digest(digest, expected):
                print("Them:", msg)
            else:
                print("mensagem comprometida! (Falha na Integridade)")
        
        except Exception as e:
            print(f"Erro inesperado no recebimento: {e}")
            break


def start_p2p_listener(my_user, my_pass):
    """Inicia o listener P2P para aceitar conexões entrantes."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile="ca_cert.pem")
    context.load_cert_chain(certfile=f"{my_user}_cert.pem", keyfile=f"{my_user}_key.pem")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', P2P_PORT))
    server.listen()
    print(f"Servidor P2P de {my_user} escutando na porta {P2P_PORT}...")

    try:
        conn, addr = server.accept()
        client = context.wrap_socket(conn, server_side=True)

        if not authenticate_peer(client, my_user, my_pass, is_initiator=True):
            client.close()
            return
        
        if not perform_key_exchange(client, is_initiator=True):
            client.close()
            return
        
        P2P_IS_CONNECTED.set() 
        
        print(f"\n--- CHAT P2P COM {addr[0]} INICIADO (HOST) ---")
        threading.Thread(target=send_messages, args=(client,), daemon=True).start()
        threading.Thread(target=receive_messages, args=(client,), daemon=True).start()
        
    except Exception as e:
        print(f"Erro no listener P2P: {e}")
    finally:
        server.close()
        return


def coordinate_and_chat(my_user, my_pass):
    threading.Thread(target=start_p2p_listener, args=(my_user, my_pass), daemon=True).start()

    coord_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        coord_sock.connect((COORD_IP, COORD_PORT))
    except ConnectionRefusedError:
        print(f"erro: Servidor de Coordenação não está rodando em {COORD_IP}:{COORD_PORT}")
        return

    login_msg = f"LOGIN|{my_user}|{my_pass}|{P2P_PORT}" 
    coord_sock.send(login_msg.encode())
    
    response = coord_sock.recv(1024).decode()
    if not response.startswith("OK"):
        print(f"falha no login de coordenação: {response}")
        coord_sock.close()
        return
        
    print(f"conectado ao Servidor de Coordenação. Usuário **{my_user}** ONLINE.")
    while True:
        if P2P_IS_CONNECTED.is_set():
            print("\nHost: Conexão P2P estabelecida. Desconectando da Coordenação.")
            break 
            
        try:
            coord_sock.send(b"GET_LIST")
            coord_sock.settimeout(5)
            
            data = coord_sock.recv(1024).decode()
            
            if not data.startswith("LIST"):
                print("falha ao receber lista do servidor. Desconectando.")
                break
                
            _, json_list = data.split("|", 1)
            available_users_data = json.loads(json_list)
            
            if not available_users_data:
                print("\nNenhum outro usuário online. (Aguardando conexões...)")
                time.sleep(5) 
                continue
                
            print("\n--- USUÁRIOS ONLINE ---")
            available_users_names = list(available_users_data.keys())
            for i, user in enumerate(available_users_names):
                print(f"{i+1}: {user}")
            
            choice = input("Digite o número do usuário para iniciar o chat ou (R) para Recarregar: ").strip().upper()
            
            if choice == 'R':
                time.sleep(1) 
                continue
                
            if choice.isdigit():
                user_index = int(choice) - 1
                if 0 <= user_index < len(available_users_names):
                    target_user = available_users_names[user_index]

                    target_info = available_users_data[target_user]
                    target_ip = target_info["ip"]
                    target_port = target_info["port"]
                    
                    print(f"tentando iniciar chat P2P seguro com {target_user}...")
                    
                    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH) 
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.load_verify_locations(cafile="ca_cert.pem")
                    context.load_cert_chain(certfile=f"{my_user}_cert.pem", keyfile=f"{my_user}_key.pem")

                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client = context.wrap_socket(client, server_hostname='localhost') 
                    
                    try:
                        client.connect((target_ip, target_port)) 
                    except ConnectionRefusedError:
                        print(f"erro: O peer {target_user} não está escutando na porta {P2P_PORT}.")
                        client.close()
                        continue
                        
                    if not authenticate_peer(client, my_user, my_pass, is_initiator=False):
                        client.close()
                        continue
                        
                    if not perform_key_exchange(client, is_initiator=False):
                        client.close()
                        continue

                    global P2P_CLIENT_SOCKET
                    P2P_CLIENT_SOCKET = client

                    print(f"\n--- CHAT P2P COM {target_user} INICIADO (CONNECT) ---")
                    
                    threading.Thread(target=send_messages, args=(client,), daemon=True).start()
                    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

                    P2P_IS_CONNECTED.set()
                    break 

                else:
                    print("Seleção inválida.")
                    time.sleep(1)
            
            else:
                print("Seleção inválida.")
                time.sleep(1)

        except socket.timeout:
            continue
        except Exception as e:
            print(f"Erro no loop de coordenação: {e}")
            break

    coord_sock.send(b"QUIT")
    coord_sock.close()
    
    if P2P_IS_CONNECTED.is_set():
        print("Thread de Coordenação encerrada. Chat P2P ativo.")
        
    return


if __name__ == '__main__':
    
    my_user = input("Seu usuário: ").strip()
    my_pass = input("Sua senha: ").strip()
    
    coordinate_and_chat(my_user, my_pass)

    while True:
        time.sleep(1)