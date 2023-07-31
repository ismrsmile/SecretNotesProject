from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet

window = Tk()
window.title("BMI Calculator")
window.minsize(width=280, height=400)
window.config(padx=20, pady=20)

# Şifreleme ve çözme için anahtar oluşturma
def generate_key():
    return Fernet.generate_key()

# Şifreleme fonksiyonu
def encrypt_message(key, message):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

# Şifre çözme fonksiyonu
def decrypt_message(key, encrypted_message):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

# "Save & Encrypt" butonuna basıldığında çalışacak fonksiyon
def save_and_encrypt():
    title = title_entry.get()
    secret = secret_text.get("1.0", "end-1c")  # Text widget'tan veriyi almak için böyle kullanırız
    key = secret_entry.get()

    if not title or not secret or not key:
        messagebox.showerror("Hata", "Lütfen tüm alanları doldurun!")
        return

    # Anahtar oluşturma
    key = generate_key()

    # Mesajı şifreleme
    encrypted_message = encrypt_message(key, secret)

    # Verileri dosyaya kaydetme
    with open("encrypted_data.txt", "w") as file:
        file.write(f"Title: {title}\n")
        file.write(f"Master Key: {key.decode()}\n")
        file.write(f"Encrypted Message: {encrypted_message.decode()}\n")

    messagebox.showinfo("Başarılı", "Veriler şifrelenerek kaydedildi!")

def decrypt_data():
    title = title_entry.get()
    secret = secret_text.get("1.0", "end-1c")
    key = secret_entry.get()

    if not secret or not key:
        messagebox.showwarning("Hata", "Lütfen tüm alanları doldurun!")
        return

    # Şifreyi çözme işlemi
    try:
        decrypted_message = decrypt_message(key.encode(), secret.encode())
        secret_text.delete("1.0", "end")  # Önceki içeriği temizle
        secret_text.insert("1.0", decrypted_message)  # Çözülmüş mesajı göster
    except Exception as e:
        messagebox.showerror("Hata", "Şifre çözme işlemi başarısız oldu. Lütfen geçerli bir anahtar ve şifre girin.")

#Resim ekleme
image_path = "image.png"

image = PhotoImage(file=image_path)
resized_image = image.subsample(4, 4)
image_label = Label(window, image=resized_image)
image_label.pack()

#Kullanıcıdan başlık alma
title_label = Label(text="Enter your title",font="Arial, 13")
title_label.pack(pady=5)

title_entry = Entry(width=32)
title_entry.pack()

#Kullanıcıdan sırrını alma
secret_label = Label(text="Enter your secret",font="Arial, 13")
secret_label.pack(pady=5)

secret_text = Text(width=32,height=13)
secret_text.pack()

#Kullanıcıdan anahtarını alma
key_label = Label(text="Enter master key",font="Arial, 13")
key_label.pack(pady=5)

secret_entry = Entry(width=27)
secret_entry.pack(pady=5)

#Kaydetme ve şifreleme butonu
save_encrypt_button = Button(text="Save & Encrypt", command=save_and_encrypt)
save_encrypt_button.pack(pady=5)

#Şifreyi çözme butonu
decrypt_button = Button(text="Decrypt", command=decrypt_data)
decrypt_button.pack(pady=5)

window.mainloop()