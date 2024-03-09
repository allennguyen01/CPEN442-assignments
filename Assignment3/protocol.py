import os
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import poly1305
from cryptography.fernet import Fernet

# When Client presses "Secure Connection", GetProtocolInitiationMessage is called
# This is sent via _SendMessage in app.py which calls EncryptAndProtectMessage
# This is sent to the server, which first checks the message calling IsMessagePartOfProtocol
# If yes, the server calls ProcessReceivedProtocolMessage
# Otherwise, the server calls DecryptAndVerifyMessage
# 
NONCE_LENGTH = 16
SESSION_KEY_LENGTH = 32
STATE = {
    "INSECURE": 0,
    "INITIATED": 1,
    "SECURE": 3
}

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self , sharedSecret, hostName):
        self.sharedSecret = sharedSecret
        self.hostName = hostName
        self.key = None # Session key
        self.nonce = None
        self.receivedNonce = None
        self.isClient = None
        self.receivedHostName = None

    # Setting the host type (client or server)
    def setHostType(self, host_type):
        self.isClient = (host_type == "client")

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, isClient):
        self.nonce = os.urandom(NONCE_LENGTH)
        encodedHostName = self.hostName.encode()
        cipher = Fernet(self._sharedSecret)
       
        if isClient:
            if self.state == "INSECURE":
            #  Ra , "I'm Alice"
                return  self.nonce + encodedHostName 
            elif self.state == "INITIATED":
            # E("Alice", Rb, Ks, Kab)
                return cipher.encrypt(encodedHostName + self.key + self.receivedNonce)
        else: # server
            # Rb, E(Ra, Ks, "Bob", Kab)
            self.SetSessionKey()
            return self.nonce + cipher.encrypt(self.receivedNonce + self.key + encodedHostName)

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLEMENT THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        check = True
        return check


    # Processing protocol message
    # TODO: IMPLEMENT THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        if not self.isClient: # server receives message from client
        # Extracting hostName and nonce
            if self.state == "INSECURE": # server receives Client host name, Ra
                self.receivedNonce = message[:NONCE_LENGTH]     #supposed to receive Ra
                self.receivedHostName = message[NONCE_LENGTH:].decode() #supposed to receive "Alice"
            elif self.state == "INITIATED": 
                cipher = Fernet(self._sharedSecret)
                decryptedMessage = cipher.decrypt(message)
                
                #decryptedMessage = (receivedNonce, receivedHostName)
                self.newReceivedNonce = decryptedMessage[:NONCE_LENGTH]
                self.newReceivedHostName = decryptedMessage[NONCE_LENGTH:].decode()

                #authentication check
                if (self.newReceivedNonce != self.receivedNonce) or (self.newReceivedHostName != self.receivedHostName):
                    raise Exception("Authentication failed")
                        
        else: #client receives Rb, E(Ra, Ks,"Bob" Kab)
            
            self.receivedNonce = message[:NONCE_LENGTH]
            cipher = Fernet(self._sharedSecret)
            decryptedMessage = cipher.decrypt(message).decode()
            newReceivedNonce = self.decryptedMessage[:NONCE_LENGTH] #supposed to receive Ra
            newReceivedHostName = self.decryptedMessage[NONCE_LENGTH+SESSION_KEY_LENGTH:]

            #authentication check
            if (newReceivedNonce != self.receivedNonce) or (newReceivedHostName != self.receivedHostName):
                raise Exception("Authentication failed")          
            self.key = self.decryptedMessage[NONCE_LENGTH:NONCE_LENGTH+SESSION_KEY_LENGTH]
            

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self):
        return secrets.token_bytes(SESSION_KEY_LENGTH)
        
        
    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        # cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        # encryptor = cipher.encryptor()
        # cipher_text = encryptor.update(plain_text) + encryptor.finalize()

        # return cipher_text

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
        
        # cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        # decryptor = cipher.decryptor()
        # plain_text = decryptor.update(cipher_text) + decryptor.finalize()


        # return plain_text
        
        return plain_text
