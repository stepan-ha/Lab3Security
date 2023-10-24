import tkinter as tk
from tkinter import filedialog
from Randomizer import  Randomizer
from MyMD5 import  MyMD5
from  RC5 import RC5

mmd = MyMD5()
rnd = Randomizer()
rc5 = RC5()

def get_key_from_password(password, key_length):
    password_hash = mmd.md5(bytearray(password, "utf8"))
    print(password_hash)
    if key_length == 8:
        return password_hash[:8]
    elif key_length == 16:
        return password_hash + mmd.md5(bytearray(password_hash, "utf8"))

def encrypt_file(input_file, output_file, key):
    block_size = 64
    with open(input_file, 'rb') as file_in, open(output_file, 'wb') as file_out:
        rc5.encrypt_file(block_size, key, 12, file_in, file_out)
def decrypt_file(input_file, output_file, key):
    block_size = 64
    with open(input_file, 'rb') as file_in, open(output_file, 'wb') as file_out:
        rc5.decrypt_file(block_size, key, 12, file_in, file_out)

def encrypt_button_click():
    password = password_entry.get()
    input_file = filedialog.askopenfilename()
    output_file = filedialog.asksaveasfilename()

    key = get_key_from_password(password, 8)
    encrypt_file(input_file, output_file, key)
    status_label.config(text="Файл зашифровано успішно.")

def decrypt_button_click():
    password = password_entry.get()
    input_file = filedialog.askopenfilename()
    output_file = filedialog.asksaveasfilename()

    key = get_key_from_password(password, 8)
    decrypt_file(input_file, output_file, key)
    status_label.config(text="Файл розшифровано успішно.")

window = tk.Tk()
window.title("Шифрування та дешифрування файлів")

password_label = tk.Label(window, text="Парольна фраза:")
password_label.pack()
password_entry = tk.Entry(window, show="*")
password_entry.pack()

encrypt_button = tk.Button(window, text="Шифрувати", command=encrypt_button_click)
encrypt_button.pack()
decrypt_button = tk.Button(window, text="Дешифрувати", command=decrypt_button_click)
decrypt_button.pack()

status_label = tk.Label(window, text="")
status_label.pack()

window.mainloop()