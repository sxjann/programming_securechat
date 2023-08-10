import pickle
import socket
import threading
import tkinter
from tkinter.constants import RIGHT
import tkinter.scrolledtext
from tkinter import simpledialog
from Crypto.Cipher import AES
import rsa

host_ip = socket.gethostname()    
host_port = 5555



class Client:
    def __init__(self,hostIP,port):
        msg=tkinter.Tk()
        msg.withdraw()

        self.nickname= simpledialog.askstring("Nickname", "please choose a nickaname", parent=msg) 
        (self.public_key,self.private_key)=rsa.newkeys(512) 
        
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.connect((hostIP,port))


        self.gui_done = False
        self.running = True
        
        msg.destroy()

        gui_thread= threading.Thread(target=self.gui_loop)
        receive_thread= threading.Thread(target=self.receive)

        gui_thread.start()
        receive_thread.start()

    def gui_loop(self):
        self.window=tkinter.Tk()
        self.window.title("Secure Message Application")
        self.window.resizable(width=False, height=False)
        self.window.configure()

        self.chat_label = tkinter.Label(self.window,text="Message Application", font=("Times", 30, "bold italic"))
        self.chat_label.pack(padx=20,pady=5)

        self.text_area=tkinter.scrolledtext.ScrolledText(self.window)
        self.text_area.pack(padx=20,pady=5)
        self.text_area.config(state='disabled') 
        
        self.input_area = tkinter.Text(self.window,height=3)
        self.input_area.pack(padx=20,pady=5)
        
        self.button_img = tkinter.PhotoImage(file=r"C:\Users\kcsaj\OneDrive\Desktop\New folder\boton.png")
        self.send_button = tkinter.Button(self.window, text="send", command = self.write, image = self.button_img, highlightthickness = 0, bd = 0)
        self.send_button.pack()

        self.chat_label = tkinter.Label(self.window,text="World best secure message application", font=("Times", 8))
        self.chat_label.pack(anchor='w')

        self.gui_done=True
        self.window.mainloop()

    def write(self):
        if len(self.input_area.get('1.0','end')) > 1 :  
            message = f"{self.nickname}: {self.input_area.get('1.0','end')}"    
            
            cipher = AES.new(self.symetric_key, AES.MODE_EAX)   
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))

            tupled_data = pickle.dumps((ciphertext,nonce,tag))  
            self.sock.send(tupled_data)

            self.input_area.delete('1.0','end') 
    
    def stop(self):
        self.running=False
        self.window.destroy()
        self.sock.close()
        exit(0)

    def receive(self):
        while self.running:
            try:
                message = pickle.loads(self.sock.recv(1024))

                if message == 'NICK':
                    self.sock.send(pickle.dumps(self.nickname))
                
                elif message == 'PUBLIC KEY':
                    public_key_in_bytes=pickle.dumps(self.public_key) 
                    self.sock.send(public_key_in_bytes)

                    wait_for_symetric_key = True
                    while wait_for_symetric_key:   
                        message = self.sock.recv(1024)
                        self.symetric_key = pickle.loads(rsa.decrypt(message,self.private_key)).encode('utf-8')
                        wait_for_symetric_key = False
                        
                
                elif type(message) is tuple:  
                    
                    cipher = AES.new(self.symetric_key, AES.MODE_EAX, nonce=message[1])
                    plaintext = cipher.decrypt(message[0])
                    try:
                        cipher.verify(message[2])
                    except ValueError:
                        pass
                    if self.gui_done:
                        self.text_area.config(state='normal')
                        self.text_area.insert('end',plaintext)
                        self.text_area.yview('end')
                        self.text_area.config(state='disabled')

            except ConnectionAbortedError:
                break
            except:
                print("Error")
                self.sock.close()
                break

client= Client(host_ip,host_port)  