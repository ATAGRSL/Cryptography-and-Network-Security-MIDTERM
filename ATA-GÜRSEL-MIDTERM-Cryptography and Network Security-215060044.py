from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import os

# Anahtarları saklamak için bir dizin belirtin
anahtar_dizini = "anahtarlar/"

# Dizin yoksa oluşturun
if not os.path.exists(anahtar_dizini):
    os.makedirs(anahtar_dizini)

# Anahtar dosyalarının tam yolu
private_key_path = os.path.join(anahtar_dizini, "private_key.pem")
public_key_path = os.path.join(anahtar_dizini, "public_key.pem")

# Anahtarları oluşturmak için bir fonksiyon
def anahtar_olustur():
    # RSA anahtar çifti oluşturma
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Genel anahtarın ve özel anahtarın dosyalara kaydedilmesi
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(private_pem)

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, "wb") as public_key_file:
        public_key_file.write(public_pem)
    print("Anahtarlar başarıyla oluşturuldu ve saklandı.")

# Anahtarları yüklemek için bir fonksiyon
def anahtar_yukle():
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(private_key_file.read(), password=None, backend=default_backend())
        with open(public_key_path, "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(public_key_file.read(), backend=default_backend())
        return private_key, public_key
    else:
        return None, None

# Dosyayı şifrelemek için bir fonksiyon
def dosyayi_sifrele(dosya_adi, public_key):
    try:
        with open(dosya_adi, "rb") as file:
            icerik = file.read()
            ciphertext = public_key.encrypt(
                icerik,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

        # Şifrelenmiş veriyi aynı dosya üzerine yazın
        with open(dosya_adi, "wb") as dosya:
            dosya.write(ciphertext)
        print(f"{dosya_adi} dosyası başarıyla şifrelendi.")

    except FileNotFoundError:
        print(f"{dosya_adi} adlı dosya bulunamadı.")

# Dosyayı çözmek için bir fonksiyon
def dosyayi_coz(sifreli_dosya_adi, private_key):
    try:
        with open(sifreli_dosya_adi, "rb") as sifreli_file:
            ciphertext = sifreli_file.read()
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

        # Çözülen veriyi aynı dosya üzerine yazın
        with open(sifreli_dosya_adi, "wb") as dosya:
            dosya.write(plaintext)
        print(f"{sifreli_dosya_adi} dosyası başarıyla çözüldü.")

    except FileNotFoundError:
        print(f"{sifreli_dosya_adi} adlı dosya bulunamadı.")

# Ana işlem döngüsü
while True:
    print("\n1 - Anahtar Oluştur")
    print("2 - Dosyayı Şifrele")
    print("3 - Dosyayı Çöz")
    print("4 - Çıkış")

    secim = input("Yapmak istediğiniz işlemi seçin: ")

    if secim == "1":
        anahtar_olustur()
    elif secim == "2":
        private_key, public_key = anahtar_yukle()
        if public_key is not None:
            dosya_adi = input("Şifrelemek istediğiniz dosyanın adını girin: ")
            dosyayi_sifrele(dosya_adi, public_key)
        else:
            print("Anahtarlar bulunamadı. Lütfen önce anahtarları oluşturun.")
    elif secim == "3":
        private_key, public_key = anahtar_yukle()
        if private_key is not None:
            sifreli_dosya_adi = input("Çözmek istediğiniz şifreli dosyanın adını girin: ")
            dosyayi_coz(sifreli_dosya_adi, private_key)
        else:
            print("Anahtarlar bulunamadı. Lütfen önce anahtarları oluşturun.")
    elif secim == "4":
        break
    else:
        print("Geçersiz seçenek. Lütfen tekrar deneyin.")
