import socket
import ssl
import threading
import hmac
import hashlib

# Usuários e senhas
USERS = {"alice": "1234", "bob": "abcd"}

# Função para gerar HMAC de senha
def hmac_password(username, password):
    return hmac.new(username.encode(), password.encode(), hashlib.sha256).hexdigest()

# Chave secreta para HMAC de mensagens (pode ser trocada via DH)
SECRET_KEY = b"segredo123"

# ----- Funções de envio e recebimento de mensagens -----
def send_messages(sock):
    while True:
        msg = input()
        digest = hmac.new(SECRET_KEY, msg.encode(), hashlib.sha256).hexdigest()
        sock.send(f"{msg}|{digest}".encode())
        print("You:", msg)

def receive_messages(sock):
    while True:
        data = sock.recv(1024).decode()
        if not data:
            break
        try:
            msg, digest = data.rsplit("|", 1)
            expected = hmac.new(SECRET_KEY, msg.encode(), hashlib.sha256).hexdigest()
            if hmac.compare_digest(digest, expected):
                print("Them:", msg)
            else:
                print("Mensagem comprometida!")
        except ValueError:
            print("Mensagem inválida recebida!")

# ----- Autenticação mútua P2P -----
def authenticate_peer(sock, my_user, my_pass, is_initiator):
    """Retorna True se ambos os lados autenticarem corretamente"""
    my_hmac = hmac_password(my_user, my_pass)

    if is_initiator:
        # Envia primeiro
        sock.send(f"{my_user}|{my_hmac}".encode())
        data = sock.recv(1024).decode()
    else:
        # Recebe primeiro
        data = sock.recv(1024).decode()
        sock.send(f"{my_user}|{my_hmac}".encode())

    # Verifica o peer
    try:
        peer_user, peer_hmac = data.split("|")
        expected = hmac_password(peer_user, USERS.get(peer_user, ""))
        if hmac.compare_digest(peer_hmac, expected):
            sock.send(b"OK")
            print(f"Peer {peer_user} autenticado!")
        else:
            sock.send(b"FAIL")
            print(f"Falha na autenticação do peer {peer_user}")
            return False
    except Exception as e:
        print("Erro na autenticação:", e)
        return False

    # Recebe confirmação final
    resp = sock.recv(1024).decode()
    return resp == "OK"

# ----- Escolha do modo -----
choice = input("Host (1) or Connect (2)? ")
my_user = input("Seu usuário: ").strip()
my_pass = input("Sua senha: ").strip()

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if choice == '1' else ssl.Purpose.SERVER_AUTH)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

if choice == '1':
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('192.168.0.82', 9999))
    server.listen()
    print("Aguardando conexão...")
    conn, addr = server.accept()
    client = conn #Sem TLS
    #client = context.wrap_socket(conn, server_side=True) #Com TLS
    if not authenticate_peer(client, my_user, my_pass, is_initiator=True):
        client.close()
        exit()
else:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #client = context.wrap_socket(client, server_hostname='localhost')
    client.connect(('192.168.0.82', 9999))
    if not authenticate_peer(client, my_user, my_pass, is_initiator=False):
        client.close()
        exit()

# ----- Inicia threads de envio e recebimento -----
threading.Thread(target=send_messages, args=(client,), daemon=True).start()
threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

# Mantém o programa rodando
while True:
    pass
