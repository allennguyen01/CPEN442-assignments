# system imports
import sys
import socket
from threading import Thread
import pygubu
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox
import re
# local import from "protocol.py"
from protocol import Protocol

STATE = {
    "INSECURE": 0,
    "INITIATED": 1,
    "SECURE": 2
}

class Assignment3VPN:
    # Constructor
    def __init__(self, master=None):
        # Initializing UI
        self.builder = builder = pygubu.Builder()
        builder.add_from_file("UI.ui")
        
        # Getting references to UI elements
        self.mainwindow = builder.get_object('toplevel', master)
        self.hostNameEntry  = builder.get_object('ipEntry', self.mainwindow)
        self.connectButton  = builder.get_object('connectButton', self.mainwindow)
        self.secureButton  = builder.get_object('secureButton', self.mainwindow)
        self.clientRadioButton = builder.get_object('clientRadioButton', self.mainwindow)
        self.serverRadioButton = builder.get_object('serverRadioButton', self.mainwindow)
        self.ipEntry = builder.get_object('ipEntry', self.mainwindow)
        self.portEntry = builder.get_object('portEntry', self.mainwindow)
        self.secretEntry = builder.get_object('secretEntry', self.mainwindow)
        self.sendButton = builder.get_object('sendButton', self.mainwindow)
        self.logsText = builder.get_object('logsText', self.mainwindow)
        self.messagesText = builder.get_object('messagesText', self.mainwindow)
        
        # Getting bound variables
        self.mode = None
        self.hostName = None
        self.port = None
        self.sharedSecret = None
        self.textMessage = None
        builder.import_variables(self, ['mode', 'hostName', 'port', 'sharedSecret', 'textMessage'])               
        builder.connect_callbacks(self)
        
        # Network socket and connection
        self.s = None
        self.conn = None
        self.addr = None
        
        # Add attributes
        self.authState = STATE["INSECURE"]
        self.isClient = None
        
        # Server socket threads
        self.server_thread = Thread(target=self._AcceptConnections, daemon=True)
        self.receive_thread = Thread(target=self._ReceiveMessages, daemon=True)
        
        # Creating a protocol object
        self.prtcl = Protocol(sharedSecret=self.sharedSecret, hostName=self.hostName)
     
    # Distructor     
    def __del__(self):
        # Closing the network socket
        if self.s is not None:
            self.s.close()
            
        # Killing the spawned threads
        if self.server_thread.is_alive():
            self.server_thread.terminate()
        if self.receive_thread.is_alive():
            self.receive_thread.terminate()
            
    
    # Handle client mode selection
    def ClientModeSelected(self):
        self.hostName.set("localhost")
        self.isClient = True
        self.prtcl.setHostType("client")


    # Handle sever mode selection
    def ServerModeSelected(self):
        self.isClient = False
        self.prtcl.setHostType("server")


    # Create a TCP connection between the client and the server
    def CreateConnection(self):
        # Change button states
        self._ChangeConnectionMode()
        
        # Create connection
        if self._CreateTCPConnection():
            if self.mode.get() == 0:
                # enable the secure and send buttons
                self.secureButton["state"] = "enable"
                self.sendButton["state"] = "enable"
        else:
            # Change button states
            self._ChangeConnectionMode(False)


    # Establish TCP connection/port
    def _CreateTCPConnection(self):
        if not self._ValidateConnectionInputs():
            return False
        
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.mode.get() == 0:
                self._AppendLog("CONNECTION: Initiating client mode...")
                self.s.connect((self.hostName.get(), int(self.port.get())))
                self.conn = self.s
                self.receive_thread.start()
                self._AppendLog("CLIENT: Connection established successfully. You can now send/receive messages.")
            else:
                self._AppendLog("CONNECTION: Initiating server mode...")
                self.s.bind((self.hostName.get(), int(self.port.get())))
                self.s.listen(1)
                self.server_thread.start()
            return True
        except Exception as e:
            self._AppendLog("CONNECTION: connection failed: {}".format(str(e)))
            return False
            
     
    # Accepting connections in a separate thread
    def _AcceptConnections(self):
        try:
            # Accepting the connection
            self._AppendLog("SERVER: Waiting for connections...")
            self.conn, self.addr = self.s.accept()
            self._AppendLog("SERVER: Received connection from {}. You can now send/receive messages".format(self.addr))
            
            # Starting receiver thread
            self.receive_thread.start()
            
            # Enabling the secure and send buttons
            self.secureButton["state"] = "enable"
            self.sendButton["state"] = "enable"
        except Exception as e:
            self._AppendLog("SERVER: Accepting connection failed: {}".format(str(e)))
            return False


    # Receive data from the other party
    def _ReceiveMessages(self):
        while True:
            try:
                # Receiving all the data
                cipher_text = self.conn.recv(4096)
                
                plain_text = cipher_text

                # Check if socket is still open
                if cipher_text == None or len(cipher_text) == 0:
                    self._AppendLog("RECEIVER_THREAD: Received empty message")
                    break
                 
                # Checking if the received message is part of your protocol
               
                if self.prtcl.IsMessagePartOfProtocol(cipher_text.decode()) and self.authState != STATE["SECURE"]:
                    # Disabling the button to prevent repeated clicks
                    self.secureButton["state"] = "disabled"
                    self._AppendLog(f'RECEIVER_THREAD: Received protocol message{cipher_text.decode()}')
                    # Check if the host is a server
                    if not self.isClient:
                        # Processing the protocol message

                        if self.authState == STATE["INSECURE"]:
                            self.prtcl.ProcessReceivedProtocolMessage(cipher_text, self.authState)
                            res = self.prtcl.GetProtocolInitiationMessage(self.isClient, self.authState)
                            self._SendMessage(message=res, bootstrap=True)
                            self.authState = STATE["INITIATED"]

                        # Protocol message will be last received and does not require a response
                        else:
                            self.authState = STATE["SECURE"]
                            self._AppendLog("SERVER: Secure connection established.")

                    else:
                        # Processing the protocol message
                        self.prtcl.ProcessReceivedProtocolMessage(cipher_text, self.authState)
                        res = self.prtcl.GetProtocolInitiationMessage(self.isClient, self.authState)
                        
                        self._SendMessage(message=res, bootstrap=True)
                        self.authState = STATE["SECURE"]
                        self._AppendLog("CLIENT: Secure connection established.")

                # Otherwise, decrypting and showing the messaage
                else:
                    if self.authState == STATE["SECURE"]:
                        plain_text = self.prtcl.DecryptAndVerifyMessage(cipher_text)
                        plain_text = self._sanitize_input(plain_text.decode())
                        plain_text = plain_text.encode()
                    if type(plain_text) == bytes:
                        self._AppendMessage("Other: {}".format(plain_text.decode()))
                    else:
                        self._AppendMessage("Other: {}".format(plain_text))
                    
            except Exception as e:
                self._AppendLog("RECEIVER_THREAD: Error receiving data: {}".format(str(e)))
                return False


    

    def _sanitize_input(self,input_string):
        # Define a regular expression pattern to match special characters
        pattern = re.compile(r'[;\'"<>]')
        # Replace special characters with empty string
        sanitized_string = re.sub(pattern, '', input_string)
        return sanitized_string

    # Send data to the other party
    def _SendMessage(self, message, bootstrap=False):
   
        if not(bootstrap):
            plain_text = message
            cipher_text = self.prtcl.EncryptAndProtectMessage(plain_text)
            
            if type(cipher_text) == bytes:
                self.conn.send(cipher_text)
            else:
                self.conn.send(cipher_text.encode())
        else:
            if type(message) == bytes:
                self.conn.send(message)
            else:
                self.conn.send(message.encode())

    # Secure connection with mutual authentication and key establishment
    def SecureConnection(self):
        # Check if the server is trying to initiate the secure connection
        if not self.isClient:
            self._AppendLog("SECURE_CONNECTION: Server cannot initiate secure connection. Please wait for the client to initiate the connection.")
        
        # Check if the connection is already secure
        elif self.authState == STATE["SECURE"]:
            self._AppendLog("SECURE_CONNECTION: Connection is already secure.")

        # Check if the secure connection is already initiated
        elif self.authState == STATE["INITIATED"]:
            self._AppendLog("SECURE_CONNECTION: Secure connection is already initiated.")

        else:
            # disable the button to prevent repeated clicks
            self.secureButton["state"] = "disabled"

            # TODO: THIS IS WHERE YOU SHOULD IMPLEMENT THE START OF YOUR MUTUAL AUTHENTICATION AND KEY ESTABLISHMENT PROTOCOL, MODIFY AS YOU SEEM FIT
            init_message = self.prtcl.GetProtocolInitiationMessage(isClient=self.isClient,state=self.authState)
            self.authState = STATE["INITIATED"]
            self._SendMessage(message=init_message, bootstrap=True) 

    # Called when SendMessage button is clicked
    def SendMessage(self):
        # Check if the connection is still being established
        if self.authState == STATE["INITIATED"]:
            messagebox.showerror("Networking", "Initializing secure connection. Please wait for the secure connection to be established.")
            return
        
        text = self.textMessage.get()
        if  text != "" and self.s is not None:
            try:
                self._SendMessage(text, self.authState == STATE["INSECURE"])
                self._AppendMessage("You: {}".format(text))
                self.textMessage.set("")
            except Exception as e:
                self._AppendLog("SENDING_MESSAGE: Error sending data: {}".format(str(e)))
                
        else:
            messagebox.showerror("Networking", "Either the message is empty or the connection is not established.")


    # Clear the logs window
    def ClearLogs(self):
        self.logsText.configure(state='normal')
        self.logsText.delete('1.0', tk.END)
        self.logsText.configure(state='disabled')

    
    # Append log to the logs view
    def _AppendLog(self, text):
        self.logsText.configure(state='normal')
        self.logsText.insert(tk.END, text + "\n\n")
        self.logsText.see(tk.END)
        self.logsText.configure(state='disabled')

        
    def _AppendMessage(self, text):
        self.messagesText.configure(state='normal')
        self.messagesText.insert(tk.END, text + "\n\n")
        self.messagesText.see(tk.END)
        self.messagesText.configure(state='disabled')


    # Enabling/disabling buttons based on the connection status
    def _ChangeConnectionMode(self, connecting=True):
        value = "disabled" if connecting else "enabled"
        
        # change mode changing
        self.clientRadioButton["state"] = value
        self.serverRadioButton["state"] = value
        
        # change inputs
        self.ipEntry["state"] = value
        self.portEntry["state"] = value
        self.secretEntry["state"] = value
        
        # changing button states
        self.connectButton["state"] = value

        
    # Verifying host name and port values
    def _ValidateConnectionInputs(self):
        if self.hostName.get() in ["", None]:
            messagebox.showerror("Validation", "Invalid host name.")
            return False
        
        try:
            port = int(self.port.get())
            if port < 1024 or port > 65535:
                messagebox.showerror("Validation", "Invalid port range.")
                return False
        except:
            messagebox.showerror("Validation", "Invalid port number.")
            return False
            
        return True

        
    # Main UI loop
    def run(self):
        self.mainwindow.mainloop()


# Main logic
if __name__ == '__main__':
    app = Assignment3VPN()
    app.run()
