import os
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import poly1305
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import random
# When Client presses "Secure Connection", GetProtocolInitiationMessage is called
# This is sent via _SendMessage in app.py which calls EncryptAndProtectMessage
# This is sent to the server, which first checks the message calling IsMessagePartOfProtocol
# If yes, the server calls ProcessReceivedProtocolMessage
# Otherwise, the server calls DecryptAndVerifyMessage
# 



# TBD:

# Test Authentication
# Integrity Check using MAC
# Cryptography Test


NONCE_LENGTH = 16
SESSION_KEY_LENGTH = 32
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
        self.key = None # Session key
        self.nonce = None
        self.receivedNonce = None
        self.isClient = None
        self.receivedHostName = None

        self.sharedSecret = sharedSecret.get().encode() # make it a private variable
        self.hashSharedSecret()
        self.fernet_key = base64.urlsafe_b64encode(self.sharedSecret)

    def hashSharedSecret(self):
        # Hash the sharedSecret if it's not 32 bytes
        if len(self.sharedSecret) != 32:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=os.urandom(16),
                iterations=100000,
                backend=default_backend())
          
        self.sharedSecret = kdf.derive(self.sharedSecret)

    
    # Setting the host type (client or server)
    def setHostType(self, host_type):
        self.isClient = (host_type == "client")

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, isClient, state):
        self.nonce = str(os.urandom(NONCE_LENGTH))

        hostName = self.hostName.get()
        encodedHostName = hostName.encode()
        cipher = Fernet(self.fernet_key)

        if isClient:
            if state == STATE["INSECURE"]:
            #  Ra , "I'm Alice"
                return self.nonce + hostName + AUTH_MSG
            elif state == STATE["INITIATED"]:
            # E(Rb, "Alice", Kab)
                return str(cipher.encrypt(self.receivedNonce + encodedHostName)) + AUTH_MSG
        else: # server
            # Rb, E(Ra, Ks, "Bob", Kab)
            self.SetSessionKey()

            print(f'receivedNonce: {self.receivedNonce}')
            print(f'nonce type: {type(self.receivedNonce)}')
            print(f'key: {self.key}')
            print(f'key type: {type(self.key)}')
            print(f'encodedHostName: {encodedHostName}')
            print(f'encodedHostName type: {type(encodedHostName)}')
            
            return self.nonce + str(cipher.encrypt(self.receivedNonce + self.key + encodedHostName)) + AUTH_MSG

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLEMENT THE LOGIC
    def IsMessagePartOfProtocol(self, message):  
        return (len(message) > len(AUTH_MSG) and message[-len(AUTH_MSG):] == AUTH_MSG.encode())

    # Processing protocol message
    # TODO: IMPLEMENT THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    
    def ProcessReceivedProtocolMessage(self, message, state):
        print(f'inside processing')
        if not self.isClient: # server receives message from client
        # Extracting hostName and nonce
            if state == STATE["INSECURE"]: # server receives Client host name, Ra
                self.receivedNonce = message[:NONCE_LENGTH]     #supposed to receive Ra
                self.receivedHostName = message[NONCE_LENGTH:].decode() #supposed to receive "Alice"
                
            elif state == STATE["INITIATED"]: # server receives E(Rb, "Alice", Kab)
                print(f'inside processing->server->initiated')
                cipher = Fernet(self.fernet_key)
                decryptedMessage = cipher.decrypt(message.decode()[:-len(AUTH_MSG)])
                self.newReceivedNonce = decryptedMessage[:NONCE_LENGTH]
                self.newReceivedHostName = decryptedMessage[NONCE_LENGTH:]

                print(f'decoded the newReceive')

                #authentication check
                if (self.newReceivedNonce != self.receivedNonce) or (self.newReceivedHostName != self.receivedHostName):
                    print("Authentication failed")
                    raise Exception("Authentication failed")
                        
        else: #client receives Rb, E(Ra, Ks,"Bob" Kab)
            print(f'inside processing->client')
            self.receivedNonce = message[:NONCE_LENGTH]
            print(f'receivedNonce: {self.receivedNonce}')
            cipher = Fernet(self.fernet_key)
            decoded_msg = message.decode()
            print(f'decoded_msg: {decoded_msg}')
            decoded_msg_truncated = decoded_msg[:-len(AUTH_MSG)]
            print(f'decoded_msg_truncated: {decoded_msg_truncated}')
            decryptedMessage = cipher.decrypt(decoded_msg_truncated)
            print(f'decryptedMessage: {decryptedMessage}')
            newReceivedNonce = self.decryptedMessage[:NONCE_LENGTH] #supposed to receive Ra
            print(f'newReceivedNonce: {newReceivedNonce}')
            newReceivedHostName = self.decryptedMessage[NONCE_LENGTH+SESSION_KEY_LENGTH:]
            print(f'newReceivedHostName: {newReceivedHostName}')

            #authentication check
            if (newReceivedNonce != self.receivedNonce) or (newReceivedHostName != self.receivedHostName):
                print("Authentication failed")
                raise Exception("Authentication failed")
            print("authentication successful")
            self.key = self.decryptedMessage[NONCE_LENGTH:NONCE_LENGTH+SESSION_KEY_LENGTH]


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self):
        self.key = secrets.token_bytes(SESSION_KEY_LENGTH)
        

    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        # Encrypt the plaintext with AES ECB mode
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(plain_text) + encryptor.finalize()
        
        # Generate a Poly1305 MAC for integrity protection
        p = poly1305.Poly1305(self.key)
        p.update(cipher_text)
        mac = p.finalize()

        # Append the MAC to the ciphertext
        cipher_text_with_mac = cipher_text + mac

        return cipher_text_with_mac



    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERIFICATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        
        rcvd_cipher_text = cipher_text

        cipher_text = rcvd_cipher_text[:-16]  # Assuming MAC length is 16 bytes
        received_mac = rcvd_cipher_text[-16:]  # Assuming MAC length is 16 bytes
        
        # Decrypt the ciphertext
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()
        
        # Recalculate the MAC for the received ciphertext
        p = poly1305.Poly1305(self.key)
        p.update(cipher_text)
        calculated_mac = p.finalize()
        
        # Verify the integrity by comparing the received MAC with the calculated MAC
        if calculated_mac != received_mac:
            return "Error: Integrity verification failed. Message may have been tampered with."
        

        return plain_text
