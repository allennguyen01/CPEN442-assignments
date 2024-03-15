import os
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import poly1305
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


NONCE_LENGTH = 16
NONCE_LENGTH_PADDED = 24
SESSION_KEY_LENGTH = 32
BLOCK_SIZE = 16
STATE = {
    "INSECURE": 0,
    "INITIATED": 1,
    "SECURE": 2
}
AUTH_MSG = 'uE9j7gR3pL'

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self , sharedSecret, hostName):
        self.hostName = hostName
        self.receivedNonce = None
        self.isClient = None
        self.receivedHostName = None

        self.__key = None # Session key
        self.__nonce = None
        self.__sharedSecret = sharedSecret.get().encode() # make it a private variable
        self.hashSharedSecret()       
        self.__fernet_key = base64.urlsafe_b64encode(self.__sharedSecret)


    def hashSharedSecret(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'\xd8\x8d\xf3\x1b\xe4\x1b\xf3\x88l\x17\xd7\x1d\x8d\xa1\x9f\xd1',
            iterations=100000,
            backend=default_backend())
          
        self.__sharedSecret = kdf.derive(self.__sharedSecret)


    # Setting the host type (client or server)
    def setHostType(self, host_type):
        self.isClient = (host_type == "client")
        

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    def GetProtocolInitiationMessage(self, isClient, state):
        self.__nonce = base64.b64encode(os.urandom(NONCE_LENGTH)).decode()
        hostName = self.hostName.get()
        encodedHostName = hostName.encode()
        cipher = Fernet(self.__fernet_key)

        if isClient: # client
            if state == STATE["INSECURE"]:
                #  Ra , "I'm Alice"
                return self.__nonce + hostName + AUTH_MSG
            elif state == STATE["INITIATED"]:
                # E(Rb, "Alice", Kab)
                return cipher.encrypt(self.receivedNonce.encode() + encodedHostName).decode() + AUTH_MSG
        else: # server
            # Rb, E(Ra, Ks, "Bob", Kab)
            self.SetSessionKey()
            return self.__nonce + cipher.encrypt(self.receivedNonce.encode() + self.__key + encodedHostName).decode() + AUTH_MSG


    # Checking if a received message is part of your protocol (called from app.py)
    def IsMessagePartOfProtocol(self, message):  
        return len(message) > len(AUTH_MSG) and message[-len(AUTH_MSG):] == AUTH_MSG


    # Processing protocol message
    def ProcessReceivedProtocolMessage(self, message, state):
        decoded_msg = message.decode()
        if not self.isClient: # server receives message from client
        # Extracting hostName and nonce
            if state == STATE["INSECURE"]: # server receives Client host name, Ra
                self.receivedNonce = decoded_msg[:NONCE_LENGTH_PADDED]     #supposed to receive Ra
                self.receivedHostName = decoded_msg[NONCE_LENGTH_PADDED:-len(AUTH_MSG)] #supposed to receive "Alice"
                
            elif state == STATE["INITIATED"]: # server receives E(Rb, "Alice", Kab)
                cipher = Fernet(self.__fernet_key)
                decryptedMessage = cipher.decrypt(decoded_msg[:-len(AUTH_MSG)])
                self.newReceivedNonce = decryptedMessage[:NONCE_LENGTH_PADDED]
                self.newReceivedHostName = decryptedMessage[NONCE_LENGTH_PADDED:]

                #authentication check
                if (self.newReceivedNonce.decode() != self.__nonce) or (self.newReceivedHostName.decode() != self.receivedHostName):
                    raise Exception("Authentication failed")
                        
        else: #client receives Rb, E(Ra, Ks,"Bob" Kab)
            self.receivedNonce = decoded_msg[:NONCE_LENGTH_PADDED]
            cipher = Fernet(self.__fernet_key)
            decoded_msg_truncated = decoded_msg[NONCE_LENGTH_PADDED:-len(AUTH_MSG)]
            decryptedMessage = cipher.decrypt(decoded_msg_truncated)
            newReceivedNonce = decryptedMessage[:NONCE_LENGTH_PADDED] #supposed to receive Ra
            

            #authentication check
            if (newReceivedNonce.decode() != self.__nonce):
                raise Exception("Authentication failed")
            self.__key = decryptedMessage[NONCE_LENGTH_PADDED:NONCE_LENGTH_PADDED+SESSION_KEY_LENGTH]


    # Setting the key for the current session
    def SetSessionKey(self):
        self.__key = secrets.token_bytes(SESSION_KEY_LENGTH)


    #zero padding
    def pad(self, data):
        padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
        return data + b'\x00' * padding_length
    

    def unpad(self, padded_data):
        return padded_data.rstrip(b'\x00')


    def EncryptAndProtectMessage(self, plain_text):
        # Pad the plaintext with zeros
        encoded_plain_text = plain_text.encode()
        padded_encoded_plain_text = self.pad(encoded_plain_text)

        # Generate an IV and splice it to be of block size
        iv =  base64.b64encode(os.urandom(BLOCK_SIZE))[:BLOCK_SIZE]
        cipher = Cipher(algorithms.AES(self.__key),modes.CBC(iv) ,backend=default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_encoded_plain_text) + encryptor.finalize()
        
        # Generate HMAC for integrity protection
        h = hmac.HMAC(self.__key, hashes.SHA256(), backend=default_backend())
        h.update(cipher_text)
        hmac_tag = h.finalize()

        # Append the HMAC to the ciphertext
        cipher_text_with_iv_hmac = iv + cipher_text + hmac_tag
        cipher_text_with_iv_hmac = base64.b64encode(cipher_text_with_iv_hmac)
        return cipher_text_with_iv_hmac


    def DecryptAndVerifyMessage(self, cipher_text_with_iv_hmac):
        cipher_text_with_iv_hmac = base64.b64decode(cipher_text_with_iv_hmac)
        iv = cipher_text_with_iv_hmac[:16]
        cipher_text_with_hmac = cipher_text_with_iv_hmac[16:]

        # Split the ciphertext and HMAC
        cipher_text = cipher_text_with_hmac[:-32]  # Assuming HMAC length is 32 bytes
        received_hmac_tag = cipher_text_with_hmac[-32:]  # Assuming HMAC length is 32 bytes
        
        # Decrypt the ciphertext
        cipher = Cipher(algorithms.AES(self.__key),modes.CBC(iv),backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plain_text = decryptor.update(cipher_text) + decryptor.finalize()
        
        # Unpad the plaintext
        plain_text = self.unpad(padded_plain_text)
        
        # Verify the integrity by comparing the received HMAC with the calculated HMAC
        h = hmac.HMAC(self.__key, hashes.SHA256(), backend=default_backend())
        h.update(cipher_text)   
        calculated_hmac_tag = h.finalize()
        
        if calculated_hmac_tag != received_hmac_tag:
            raise ValueError("Error: Integrity verification failed. Message may have been tampered with.")
        
        return plain_text