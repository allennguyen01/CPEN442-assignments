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
NONCE_LENGTH_PADDED = 24
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
        print(f'sharedSecret: {self.sharedSecret}')
        
        self.fernet_key = base64.urlsafe_b64encode(self.sharedSecret)
        print(f'fernet_key: {self.fernet_key}')


    def hashSharedSecret(self):
        # Hash the sharedSecret if it's not 32 bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'\xd8\x8d\xf3\x1b\xe4\x1b\xf3\x88l\x17\xd7\x1d\x8d\xa1\x9f\xd1',
            iterations=100000,
            backend=default_backend())
          
        self.sharedSecret = kdf.derive(self.sharedSecret)


    # Setting the host type (client or server)
    def setHostType(self, host_type):
        self.isClient = (host_type == "client")
        

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, isClient, state):
        print('Entered GetProtocolInitiationMessage()')
        self.nonce = base64.b64encode(os.urandom(NONCE_LENGTH)).decode()
        print(f'Generated nonce: {self.nonce}')
        print(f'Generated nonce type: {type(self.nonce)}')
        hostName = self.hostName.get()
        encodedHostName = hostName.encode()
        cipher = Fernet(self.fernet_key)

        if isClient:
            print('Entered GetProtocolInitiationMessage() -> isClient')
            if state == STATE["INSECURE"]:
                print('Entered GetProtocolInitiationMessage() -> isClient -> INSECURE')
            #  Ra , "I'm Alice"
                print(f'Returning message: {self.nonce + hostName + AUTH_MSG}')
                return self.nonce + hostName + AUTH_MSG
            elif state == STATE["INITIATED"]:
                print('Entered GetProtocolInitiationMessage() -> isClient -> INITIATED')
            # E(Rb, "Alice", Kab)
                # print(f'{ str(cipher.encrypt(self.receivedNonce + encodedHostName)) + AUTH_MSG}')
                # print(f'GetProtocolMessage->Client->Initiated State')
                print(f'Returning message: {cipher.encrypt(self.receivedNonce.encode() + encodedHostName).decode() + AUTH_MSG}')
                return cipher.encrypt(self.receivedNonce.encode() + encodedHostName).decode() + AUTH_MSG
        else: # server
            print('Entered GetProtocolInitiationMessage() -> isServer')
            # Rb, E(Ra, Ks, "Bob", Kab)
            self.SetSessionKey()
            print(f'Session key set: {self.key}')

            print(f'Beginning of the message (self.nonce): {self.nonce}')
            print(f'Encrypted 2-4th parts of the message: {cipher.encrypt(self.receivedNonce.encode() + self.key + encodedHostName).decode()}')
            print(f'Final part of the message (AUTH_MSG): {AUTH_MSG}')
            
            print(f'Returning message: {self.nonce + cipher.encrypt(self.receivedNonce.encode() + self.key + encodedHostName).decode() + AUTH_MSG}')
            return self.nonce + cipher.encrypt(self.receivedNonce.encode() + self.key + encodedHostName).decode() + AUTH_MSG

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLEMENT THE LOGIC
    def IsMessagePartOfProtocol(self, message):  
        check = len(message) > len(AUTH_MSG) and message[-len(AUTH_MSG):] == AUTH_MSG
        print(f'IsMessagePartOfProtocol: {check}')
        return check

    # Processing protocol message
    # TODO: IMPLEMENT THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    
    def ProcessReceivedProtocolMessage(self, message, state):
        print('Entered ProcessReceivedProtocolMessage()')
        # print(f'inside processing')
        print(f'Received message: {message.decode()}')
        decoded_msg = message.decode()
        if not self.isClient: # server receives message from client
            print('Entered ProcessReceivedProtocolMessage() -> server')
        # Extracting hostName and nonce
            if state == STATE["INSECURE"]: # server receives Client host name, Ra
                print('Entered ProcessReceivedProtocolMessage() -> server -> insecure')
                self.receivedNonce = decoded_msg[:NONCE_LENGTH_PADDED]     #supposed to receive Ra
                self.receivedHostName = decoded_msg[NONCE_LENGTH_PADDED:-len(AUTH_MSG)] #supposed to receive "Alice"
                print(f'Set receivedNonce: {self.receivedNonce} and receivedHostName: {self.receivedHostName}')
                
            elif state == STATE["INITIATED"]: # server receives E(Rb, "Alice", Kab)
                print('Entered ProcessReceivedProtocolMessage() -> server -> initiated')
                cipher = Fernet(self.fernet_key)
                decryptedMessage = cipher.decrypt(decoded_msg[:-len(AUTH_MSG)])
                self.newReceivedNonce = decryptedMessage[:NONCE_LENGTH_PADDED]
                self.newReceivedHostName = decryptedMessage[NONCE_LENGTH_PADDED:]
                print(f'Set receivedNonce: {self.receivedNonce} and receivedHostName: {self.newReceivedHostName}')

                #authentication check
                if (self.newReceivedNonce.decode() != self.nonce) or (self.newReceivedHostName.decode() != self.receivedHostName):
                    print("Authentication failed")
                    raise Exception("Authentication failed")
                print("Authentication successful")
                        
        else: #client receives Rb, E(Ra, Ks,"Bob" Kab)
            print(f'Entered ProcessReceivedProtocolMessage() -> client')
            self.receivedNonce = decoded_msg[:NONCE_LENGTH_PADDED]
            print(f'receivedNonce: {self.receivedNonce}')
            print(f'AUTH_MSG: {decoded_msg[-len(AUTH_MSG):]}')
            cipher = Fernet(self.fernet_key)
            print(f'decoded_msg: {decoded_msg}')
            decoded_msg_truncated = decoded_msg[NONCE_LENGTH_PADDED:-len(AUTH_MSG)]
            print(f'decoded_msg_truncated: {decoded_msg_truncated}')
            decryptedMessage = cipher.decrypt(decoded_msg_truncated)
            print(f'decryptedMessage: {decryptedMessage}')
            newReceivedNonce = decryptedMessage[:NONCE_LENGTH_PADDED] #supposed to receive Ra
            print(f'newReceivedNonce: {newReceivedNonce}')
            newReceivedHostName = decryptedMessage[NONCE_LENGTH_PADDED+SESSION_KEY_LENGTH:]
            print(f'newReceivedHostName: {newReceivedHostName}')

            #authentication check
            if (newReceivedNonce.decode() != self.nonce):
                print(f'self.nonce: {self.nonce}')
                print(f'newReceivedNonce: {newReceivedNonce}')
                print("Authentication failed")
                raise Exception("Authentication failed")
            print("Authentication successful")
            self.key = decryptedMessage[NONCE_LENGTH_PADDED:NONCE_LENGTH_PADDED+SESSION_KEY_LENGTH]


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
