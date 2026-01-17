import qrcode

fake_flag = "DSCCTF{th1s_1s_n0t_th3_fl4g}"

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_H,
    box_size=10,
    border=4,
)

qr.add_data(fake_flag)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")
img.save("qr.png")

print("[+] Fake QR generated as qr.png")
