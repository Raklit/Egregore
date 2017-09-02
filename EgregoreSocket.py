import traceback
import sys
try:
    import socket
    import struct
    import pickle
    import copy
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES
    from Crypto.Cipher import Blowfish
    from Crypto import Random
    from Crypto.Random import random
    from Crypto.Util.number import GCD
    from Crypto.Cipher import PKCS1_OAEP
except:
    print('Socket class level error: you have not some libraries.')
    traceback.print_exc()
    sys.exit(1)
else:
    print('Socket class level: All libraries was installed.')
    
class EgregoreSocket:
#   For start connection
    my_port = 8196
    conn_addr = ''
#   My keys
#   My asymmetric key len
    my_first_RSA_key_len = 4096
    my_second_RSA_key_len = 4096
#   Asymmetric
    my_private_first_RSA_key = None
    my_public_first_RSA_key = None
    my_private_second_RSA_key = None
    my_public_second_RSA_key = None
#   Symemtric
    my_AES_key = b''
    my_Blowfish_key = b'' 
#   Reciever's keys
#   Asymmetric
    conn_first_RSA_key = None
    conn_second_RSA_key = None
#   Symmetric
    conn_AES_key = b''
    conn_Blowfish_key = b''
#   Sockets
    text_socket = None
#   Logical statuses
    already_connect = False
    i_am_host = False
    possible_connection = False
    signal = False
#   Encrypters
    first_RSA_encrypter = None
    second_RSA_encrypter = None
    AES_encrypter = None
    Blowfish_encrypter = None
#   Decrypters
    first_RSA_decrypter = None
    second_RSA_decrypter = None
    AES_decrypter = None
    Blowfish_decrypter = None
    
#   Start connection's module

    def __init__(self):
        try:
            self.create()
        except:
            del self
        else:
            pass

    def create(self):
        try:
            self.text_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.text_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except:
            print('Socket creation failed.')
            self.text_socket.close()
        else:
            print('Socket creation successfully completed.')
        
    
    def bind(self,  port = 8196):
        try:
            self.my_port = port
            self.text_socket.bind(('', port))
        except:
            print('Port', self.my_port, ': Socket bind failed (already used by other process or blocked by OS).\nPlease, try other port, close other process or reboot computer.')
            self.text_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return False
        else:
            print('Port', self.my_port, ': Socket bind successfully completed.')
            return True

    
    def set_default_attrs(self):
#   For start connection
        self.my_port = 8196
        self.conn_addr = ''

#   My asymmetric key len
        self.my_first_RSA_key_len = 4096
        self.my_second_RSA_key_len = 4096

#   My keys
#   Asymmetric
        self.my_private_first_RSA_key = None
        self.my_public_first_RSA_key = None
        self.my_private_second_RSA_key = None
        self.my_public_second_RSA_key = None
#   Symemtric
        self.my_AES_key = b''
        self.my_Blowfish_key = b'' 
#   Reciever's keys
#   Asymmetric
        self.conn_first_RSA_key = None
        self.conn_second_RSA_key = None
#   Symmetric
        self.conn_AES_key = b''
        self.conn_Blowfish_key = b''
#   Sockets
        self.text_socket = None
#   Logical statuses
        self.already_connect = False
        self.i_am_host = False
        self.possible_connection = False
        self.signal = False
#   Encrypters
        self.first_RSA_encrypter = None
        self.second_RSA_encrypter = None
        self.AES_encrypter = None
        self.Blowfish_encrypter = None
#   Decrypters
        self.first_RSA_decrypter = None
        self.second_RSA_decrypter = None
        self.AES_decrypter = None
        self.Blowfish_decrypter = None
        
    
    def connect(self, addr, port = 8196):
        try:
            buf = '(\'' + addr + '\', ' + str(port) + ')'
            print('Trying to connect to ' + buf + ' ...')
            self.text_socket.settimeout(10)
            self.text_socket.connect((addr, port))
        except:
            print('Failed to connect to ' + buf + '.')
            result = False
        else:
            self.conn_addr = self.text_socket.getpeername()
            print('Connection to', self.conn_addr, 'was started.')
            self.possible_connection = True
            self.i_am_host = False
            result = True
        finally:
            self.text_socket.setblocking(True)
            return result

    def accept(self):
        try:
            print('Waiting for new connection...')
            self.text_socket.listen(1)
            self.text_socket.settimeout(45)
            self.text_socket, self.conn_addr = self.text_socket.accept()
        except:
            print("Timeout.")
            result = False
        else:
            print('New connection was detected. Address:', self.conn_addr, '.')
            self.possible_connection = True
            self.i_am_host = True
            result = True
        finally:
            self.text_socket.setblocking(True)
            return result

    def close(self):
        try:
            self.text_socket.shutdown(socket.SHUT_RDWR)
            self.text_socket.close()
        except:
            pass
        else:
            pass
        finally:
            self.set_default_attrs()
            print('Socket is closed.')
        
        
    def handshake(self):
        try:
            if not self.possible_connection:
                return False
            
            print('Start handshake...')
            first_words = b'Egregore_client_is_here'
            if self.i_am_host:
                self.text_socket.send(first_words)
                answer = self.text_socket.recv(len(first_words))
            else:
                answer = self.text_socket.recv(len(first_words))
                self.text_socket.send(first_words)
                
            if first_words == answer:
                print('It is a friend.')
                return True
            else:
                print('It is not a friend.')
                return False
        except:
            print('There are some problems. Handshake was failed.')
            return False


    def accept_call_host(self, signal):
        try:
            if signal:
                self.text_socket.send(b'\x49')
            else:
                self.text_socket.send(b'\x48')
        except:
            return False
        else:
            return True
        
    def accept_call_reciever(self):
        try:
            signal = (self.text_socket.recv(1) == b'\x49')
            return signal
        except:
            return False
        else:
            pass

    def full_connect(self, addr, port):
        self.connect(addr, port)
        if not self.possible_connection:
            self.close()
            return False
        
        handshake_result = self.handshake()
        if not handshake_result:
            self.close()
            return False

        accept_call_result = self.accept_call_reciever()
        if not accept_call_result:
            print('User refused connection or connection is broken.')
            self.close()
            return False
        
        self.key_generating()
        self.key_exchange()

        self.already_connect = True
        
        print('All the formalities are met. Good luck.')
        return True

    def pre_accept(self):
        self.accept()
        if not self.possible_connection:
            self.close()
            return False
        
        handshake_result = self.handshake()
        if not handshake_result:
            self.close()
            return False
        
        self.signal = False
        return True
        

    def full_accept(self):
        accept_call_result = self.accept_call_host(self.signal)
        if not accept_call_result:
            print('User refused connection or connection is broken.')
            self.close()
            return False
        if not self.signal:
            print('You refused connection.')
            self.close()
            return False

        self.key_generating()
        self.key_exchange()
        
        self.already_connect = True
        
        print('All the formalities are met. Good luck.')
        return True
        
#   Key generating's module
    
    def __first_RSA_key_generating(self, RSA_len = 4096):
        try:
            print('Generating of the first RSA key\'s pair ( length', RSA_len, '). Please, wait...')
            self.my_private_first_RSA_key = RSA.generate(RSA_len)
            self.my_public_first_RSA_key = self.my_private_first_RSA_key.publickey()
        except:
            print('The first RSA key generating was failed.')
        else:
            print('The first RSA key generating was completed.')
            
        
    def __second_RSA_key_generating(self, RSA_len = 4096):
        try:
            print('Generating of the second RSA key\'s pair ( length', RSA_len, '). Please, wait...')
            self.my_private_second_RSA_key = RSA.generate(RSA_len)
            self.my_public_second_RSA_key = self.my_private_second_RSA_key.publickey()
        except:
            print('The second RSA key generating was failed.')
        else:
            print('The second RSA key generating was completed.')
        

    def __AES_256_key_generating(self):
        try:
            print('Generating of AES-256 key...')
            self.my_AES_key = Random.new().read(32)
        except:
            print('AES-256 key generating was failed.')
        else:
            print('AES-256 key generating was complited.')

    def __Blowfish_448_key_generating(self):
        try:
            print('Generating of Blowfish-448 key...')
            self.my_Blowfish_key = Random.new().read(56)
        except:
            print('Blowfish-448 key generating was failed.')
        else:
            print('Blowfish-448 key generating was complited.')

    def key_generating(self):
        print("Key generating was started...")
        self.__first_RSA_key_generating(self.my_first_RSA_key_len)
        self.__second_RSA_key_generating(self.my_second_RSA_key_len)
        self.__AES_256_key_generating()
        self.__Blowfish_448_key_generating()
        print('End of key generating.')


#   Key exchange's module

    def first_RSA_encrypt(self, byte_arr):
        try:
            buf = self.first_RSA_encrypter.encrypt(byte_arr)
        except:
            print('The first RSA encryption was failed.')
            return None
        else:
            return buf

    def first_RSA_decrypt(self, byte_arr):
        try:
            buf = self.first_RSA_decrypter.decrypt(byte_arr)
        except:
            print('The first RSA decryption was failed.')
            return None
        else:
            return buf

    def second_RSA_encrypt(self, byte_arr):
        try:
            buf = self.second_RSA_encrypter.encrypt(byte_arr)
        except:
            print('The second RSA encryption was failed.')
            return None
        else:
            return buf

    def second_RSA_decrypt(self, byte_arr):
        try:
            buf = self.second_RSA_decrypter.decrypt(byte_arr)
        except:
            print('The second RSA decryption was failed.')
            return None
        else:
            return buf

    def __send_AES_key(self):
        try:
            #read RSA key
            self.conn_first_RSA_key = RSA.importKey(self.read_msg())
            #create RSA encrypter
            self.first_RSA_encrypter = PKCS1_OAEP.new(self.conn_first_RSA_key)
            #send AES key
            self.send_msg(self.first_RSA_encrypt(self.my_AES_key))
        except:
            print('Sending of AES key was failed.')
        else:
            print('Sending of AES key was complited.')

    def __read_AES_key(self):
        try:
            #create RSA decrypter
            self.first_RSA_decrypter = PKCS1_OAEP.new(self.my_private_first_RSA_key)
            #send RSA public key
            self.send_msg(self.my_public_first_RSA_key.exportKey('DER'))
            #read AES key
            self.conn_AES_key = self.first_RSA_decrypt(self.read_msg())
        except:
            print('Getting of AES key was failed.')
        else:
            print('Getting of AES key was complited.')

    def __send_Blowfish_key(self):
        try:
            #read RSA key
            self.conn_second_RSA_key = RSA.importKey(self.read_msg())
            # create RSA encrypter
            self.second_RSA_encrypter = PKCS1_OAEP.new(self.conn_second_RSA_key)
            #send Blowfish key
            self.send_msg(self.second_RSA_encrypt(self.my_Blowfish_key))
        except:
            print('Sending of Blowfish key was failed.')
        else:
            print('Sending of Blowfish key was complited.')
        
    def __read_Blowfish_key(self):
        try:
            # create RSA decrypter
            self.second_RSA_decrypter = PKCS1_OAEP.new(self.my_private_second_RSA_key)
            # send RSA public key
            self.send_msg(self.my_public_second_RSA_key.exportKey('DER'))
            #read Blowfish key
            self.conn_Blowfish_key = self.second_RSA_decrypt(self.read_msg())
        except:
            print('Getting of Blowfish key was failed.')
        else:
            print('Getting of Blowfish key was complited.')
    
    def key_exchange(self):
        try:
            print('Key exchange was started...')
            if self.i_am_host:
                self.__read_AES_key()
                self.__send_AES_key()
                self.__read_Blowfish_key()
                self.__send_Blowfish_key()
            else:
                self.__send_AES_key()
                self.__read_AES_key()
                self.__send_Blowfish_key()
                self.__read_Blowfish_key()
        except:
            print('Key exchange was failed.')
            return False
        else:
            print('Key exchange was complited.')
            return True
                        
#   Message exchange's module

#    Message format:
#    First 4 byte - length of block.
#    5'th byte - last_block's_signal (x49 aka '1' - yes and x48 aka '0' - no).
#    Last x31 byte and bytes after it are rubish (need for CBC encryption mode).
#    Other bytes - message information.

    def send_msg(self, msg):
        msg_len = len(msg)
        buf = copy.copy(msg)
        block_len = 4294967295 #2^32 - 1
        byte_like_block_len = struct.pack('N', block_len)
        n = msg_len // block_len #msg_len \ block_len
        k = msg_len % block_len #msg _len mod block_len
        if n:
            for i in n:
                msg_len -= block_len
                if not k and i == n - 1:
                    self.text_socket.send(byte_like_block_len + b'\x49' + buf[:block_len])
                else:
                    self.text_socket.send(byte_like_block_len + b'\x48' + buf[:block_len])
                buf = buf[block_len:]
            if k:
                self.text_socket.send(struct.pack('N', msg_len) + b'\x49' + buf)
        else:
            self.text_socket.send(struct.pack('N', msg_len) + b'\x49' + buf)

    def read_msg(self):
        this_is_end = False
        buf = b''
        while not this_is_end:
            block_len = struct.unpack('N', self.text_socket.recv(4))[0]
            this_is_end = (self.text_socket.recv(1) == b'\x49')
            buf += self.text_socket.recv(block_len)
        return buf

#   Message encryption's module

#   Key encryption protocol:
#   RSA encryption for AES-256 key
#   RSA enccryption for Blowfish-448 key
#   Message encryption protocol:
#   1. AES-256 text encryption (CBC mode)
#   2. Blowfish-448 text encryption (CBC mode)

    def AES_encrypt(self, msg):
        try:
            buf = copy.copy(msg)
            iv = Random.new().read(16)
            self.AES_encrypter = AES.new(self.conn_AES_key, AES.MODE_CBC, iv)
            buf =  iv + self.AES_encrypter.encrypt(buf)
        except:
            print('AES encryption was failed.')
            return None
        else:
            return buf
        
    def AES_decrypt(self, msg):
        try:
            buf = copy.copy(msg)
            iv = buf[:16]
            self.AES_decrypter = AES.new(self.my_AES_key, AES.MODE_CBC, iv)
            buf =  self.AES_decrypter.decrypt(buf[16:])
        except:
            print('AES decryption was failed.')
            return None
        else:
            return buf

    def Blowfish_encrypt(self, msg):
        try:
            buf = copy.copy(msg)
            iv = Random.new().read(8)
            self.Blowfish_encrypter = Blowfish.new(self.conn_Blowfish_key, Blowfish.MODE_CBC, iv)
            buf =  iv + self.Blowfish_encrypter.encrypt(buf)
        except:
            print('Blowfish encryption was failed.')
            return None
        else:
            return buf

    def Blowfish_decrypt(self, msg):
        try:
            buf = copy.copy(msg)
            iv = buf[:8]
            self.Blowfish_decrypter = Blowfish.new(self.my_Blowfish_key, Blowfish.MODE_CBC, iv)
            buf =  self.Blowfish_decrypter.decrypt(buf[8:])
        except:
            print('Blowfish decryption was failed.')
            return None
        else:
            return buf

    def basic_encrypt(self, msg):
        try:
            buf = copy.copy(msg)
            buf = self.AES_encrypt(buf)
            buf = self.Blowfish_encrypt(buf)
        except:
            return None
        else:
            return buf
        
    def basic_decrypt(self, msg):
        try:
            buf = copy.copy(msg)
            buf = self.Blowfish_decrypt(buf)
            buf = self.AES_decrypt(buf)
        except:
            return None
        else:
            return buf
    
    def add_len_to_n_byte_block_encryption(self, msg, n):
        msg += b'\x31'
        b = len(msg) % n
        buf = msg
        if b:
            for i in range(n - b):
                rnd_char = b'\x31'
                while (rnd_char == b'\x31'):
                    rnd_char = Random.new().read(1)
                    buf += rnd_char
        else:
            buf = copy.copy(msg)
        return buf

#   Encrypted message exchange's module

    def send(self, msg):
        try:    
            buf = copy.copy(msg)
            buf = self.add_len_to_n_byte_block_encryption(msg, 16)
            buf = self.basic_encrypt(buf)
            self.send_msg(buf)
        except:
            print("Can not send the message.")
            return False
        else:
            return True

    def recv(self):
        buf = self.basic_decrypt(self.read_msg())
        start_of_escape_chain = buf.rfind(b'\x31')
        buf = buf[0:start_of_escape_chain:]
        return buf
