import socket
import select
import sys
import base64
import os
import custom_aes
from constants import BUFFER_SIZE_FILE, IP_ADDRESS, PORT, SEPARATOR
from util import Util, AESLib

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.connect((IP_ADDRESS, PORT))


def send_file(method, filename):
    with open(filename, "rb") as file:
        server.send(f"{filename}{SEPARATOR}{method}{SEPARATOR}{os.path.getsize(os.path.abspath(filename))}".encode())
        while True:
            bytes_read = file.read(BUFFER_SIZE_FILE)
            if not bytes_read:
                break
            server.sendall(bytes_read)

def parse_and_process_message(message):
    try:
        method, command, filename = message.split(" ")
        filename = filename[:-1]
        if command == "send":
            if method == "library":
                Util.benchmark_time(lambda: AESLib.encrypt(filename))
                send_file(method, f'{filename}.b')
            elif method == "scratch":
                Util.benchmark_time(lambda: custom_aes.encrypt(filename, "cfb"))
                send_file(method, f'{filename}.b')
    except Exception as e:
        print(e)
try:
    while True:
        sockets_list = [sys.stdin, server]
        read_socket, write_socket, error_socket = select.select(sockets_list, [], [])
        
        for socks in read_socket:
            if socks == server:
                message = socks.recv(BUFFER_SIZE_FILE)
                print(message)
            else:
                message = sys.stdin.readline()
                parse_and_process_message(message)
                
            
except KeyboardInterrupt:
    server.close()
    sys.exit(0)