from tkinter import *
from tkinter import messagebox
import base64

#apply cryptography with vigenere ciphher
#https://stackoverflow.com/a/38223403

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt():
    title = title_entry.get()
    message = input_text.get("1.0", END)
    master_secret = master_secret_input.get()

    if len(title) == 0 or len(message)==0 or len(master_secret)==0 :
        messagebox.showwarning(title="Error!",message="please enter all info")

    else:
        #encryption
        message_encrypted = encode(master_secret,message)
        try:
            with open("mysecret.txt","a") as data_file:
                data_file.write(f"\n{title} \n{message_encrypted  }" )
        except FileNotFoundError:
            with open("mysecret.txt","w")as data_file:
                data_file.write(f"\n{title} \n{message_encrypted  }" )
        finally:
            title_entry.delete(0, END)
            master_secret_input.delete(0, END)
            input_text.delete("1.0", END)

def decrypt_notes():
    message_encrypted = input_text.get("1.0",END)
    master_secret = master_secret_input.get()

    if len(message_encrypted)==0 or len(master_secret) == 0:
        messagebox.showwarning(title="Error",message="Please enter all info")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            input_text.delete("1.0",END)
            input_text.insert("1.0",decrypted_message)
        except:
            messagebox.showerror(title="Error",message="please enter encrypted text !")



#UI
FONT = ("Verdana",20,"normal")
window = Tk()
photo = PhotoImage(file="TopSecret.png")
photo_label = Label(image=photo)
photo_label.pack()
"""
canvas = Canvas(height=500,width=500)
canvas.create_image(255,255,image = photo)
"""

window.title("Secret Notes")

window.config(padx=30,pady=30)

title_info_label = Label(text="Enter your title",font =FONT )
title_info_label.pack()

title_entry = Entry(width=30)
title_entry.pack()

input_info_label = Label(text="Enter your secret",font=FONT)
input_info_label.pack()

input_text = Text(width =30,height=20)
input_text.pack()

master_secret_label = Label(text="Enter your master key",font=FONT)
master_secret_label.pack()

master_secret_input = Entry(width=30)
master_secret_input.pack()


save_button = Button(text="Save & Encrypt",command=save_and_encrypt)
save_button.pack()

decrypt_button = Button(text="Decrypt",command=decrypt_notes)
decrypt_button.pack()

window.mainloop()