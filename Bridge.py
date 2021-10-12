from DataTypes import Socket_Streamer
import socket

Bandwidth = 8192

class Proxy2Server:

    def __init__(self, host, port):
        super(Proxy2Server, self).__init__()
        self.port = port
        self.host = host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        self.server = sock

        def read(self, value):
            while True:
                data = self.__socket_buffer.recv(value)
                if data:
                    break
            return data

        def write(self, value):


            return 

class Game2Proxy:

    def __init__(self, host, port):
        super(Game2Proxy, self).__init__()
        self.port = port
        self.host = host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        skt, address = sock.accept()
        self.game = skt





































            # c
