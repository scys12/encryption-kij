import socket
import selectors
import sys
import threading
import os
import custom_aes
from constants import IP_ADDRESS, PORT, SEPARATOR, BUFFER_SIZE_FILE
from util import Util, AESLib

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((IP_ADDRESS, PORT))
server.listen(100)
list_of_clients = []

def clientthread(conn, addr):
  while True:
    try:
      message = conn.recv(BUFFER_SIZE_FILE).decode()
      if message:
        filename, method, filesize = message.split(SEPARATOR)
        filename = f'received/{filename}'
        print(filename, method, filesize)
        filesize = int(filesize)
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "wb") as file:
            while True:
                message = conn.recv(min(filesize, BUFFER_SIZE_FILE))
                if not message:
                    break
                file.write(message)
                filesize -= len(message)
            file.close()
        if method == "library":
          Util.benchmark_time(lambda: AESLib.decrypt(filename))
        elif method == "scratch":
          Util.benchmark_time(lambda: custom_aes.decrypt(filename))
      else:
        remove(conn)
    except:
      continue
    
def broadcast(message, connection):
  for clients in list_of_clients:
    if clients != connection:
      try:
        clients.send(message.encode())
      except:
        clients.close()
        remove(clients)

def remove(connection):
  if connection in list_of_clients:
    list_of_clients.remove(connection)
    
try:
    while True:
        conn, addr = server.accept()
        list_of_clients.append(conn)
        print(addr[0] + 'connected')
        threading.Thread(target=clientthread, args=(conn, addr)).start()  

except KeyboardInterrupt:
    server.close()
    sys.exit(0)