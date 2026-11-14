"""
Module: run_demo.py
Quản trị giao diện dòng lệnh (CLI), bộ kiểm thử 3 ca đối chuẩn chi tiết,
mã hóa tệp tin bằng HKDF-SHA256 + AES-GCM, mô phỏng tấn công MitM và phòng chống bằng chữ ký số.
"""
import os
import sys
import time
import secrets
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from core_dh import DiffieHellmanEntity, power_mod

# Tham số chuẩn RFC 3526 MODP Group 14 (2048-bit)
RFC_3526_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
RFC_3526_P = int(RFC_3526_P_HEX, 16)
RFC_3526_G = 2


def derive_key(shared_secret: int, p: int) -> bytes:
    """
    Hàm dẫn xuất khóa HKDF-SHA-256 (RFC 5869) chuẩn mực:
    - Biểu diễn shared secret thành chuỗi byte cố định theo độ dài của p.
    - Dùng info xác định ngữ cảnh ứng dụng và tạo khóa 32 bytes (256-bit).
    """
    length = (p.bit_length() + 7) // 8
    secret_bytes = shared_secret.to_bytes(length, byteorder="big")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"DH-AES-256-file-encryption"
    )
    return hkdf.derive(secret_bytes)


def calculate_file_sha256(filepath: str) -> str:
    """Tính mã băm SHA-256 của tệp để kiểm chứng tính toàn vẹn"""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha.update(chunk)
    return sha.hexdigest()


def menu_small_number():
    print("\n" + "="*65)
    print("--- 1. DEMO BỘ SỐ NHỎ MINH HỌA (CÓ LOG TỪNG BƯỚC THUẬT TOÁN) ---")
    print("="*65)
    p, g = 23, 5
    a, b = 6, 15
    print(f"Tham số công khai: p = {p}, g = {g}")
    print(f"Khóa riêng bí mật: Alice (a = {a}), Bob (b = {b})\n")
    
    alice = DiffieHellmanEntity(p, g, private_key=a)
    bob = DiffieHellmanEntity(p, g, private_key=b)
    
    print("[*] Alice tính khóa công khai A = g^a mod p:")
    A = alice.generate_public_key(verbose=True)
    print(f"==> Kết quả Khóa công khai Alice: A = {A}\n")
    
    print("[*] Bob tính khóa công khai B = g^b mod p:")
    B = bob.generate_public_key(verbose=False)
    print(f"==> Kết quả Khóa công khai Bob: B = {B}\n")
    
    print("[*] Alice tính bí mật chung K_A = B^a mod p:")
    k_alice = alice.compute_shared_secret(B, verbose=True)
    print(f"==> Khóa bí mật chung Alice tính: K_A = {k_alice}\n")
    
    k_bob = bob.compute_shared_secret(A, verbose=False)
    print(f"==> Khóa bí mật chung Bob tính:   K_B = {k_bob}")
    
    assert k_alice == k_bob == 2, "Lỗi đối chiếu bài tính tay!"
    print("[✓] ĐỐI CHỨNG: K_A = K_B = 2 (Trùng khớp 100% kết quả tính tay lý thuyết)\n")


def menu_file_encryption():
    print("\n" + "="*65)
    print("--- 2. TRAO ĐỔI KHÓA 2048-BIT & MÃ HÓA/GIẢI MÃ TỆP TIN THỰC TẾ ---")
    print("="*65)
    file_src = "van_ban_goc.txt"
    file_enc = "van_ban_ma_hoa.bin"
    file_dec = "van_ban_khoi_phuc.txt"
    
    # Thiết lập nội dung tệp gốc chuẩn theo yêu cầu nhóm
    with open(file_src, "w", encoding="utf-8") as f:
        f.write("Nhóm 6 - ATBMTT")
    print(f"[+] Đã cập nhật nội dung tệp tin gốc ({file_src}): \"Nhóm 6 - ATBMTT\"")

    # BƯỚC 1: SINH KHÓA RIÊNG
    t0 = time.perf_counter()
    a = secrets.randbelow(RFC_3526_P - 3) + 2
    b = secrets.randbelow(RFC_3526_P - 3) + 2
    alice = DiffieHellmanEntity(RFC_3526_P, RFC_3526_G, private_key=a)
    bob = DiffieHellmanEntity(RFC_3526_P, RFC_3526_G, private_key=b)
    t_keygen = time.perf_counter() - t0

    # BƯỚC 2: TRAO ĐỔI KHÓA CÔNG KHAI VÀ TÍNH KHÓA CHUNG
    t1 = time.perf_counter()
    A = alice.generate_public_key()
    B = bob.generate_public_key()
    k_alice = alice.compute_shared_secret(B)
    k_bob = bob.compute_shared_secret(A)
    t_dh_compute = time.perf_counter() - t1

    # BƯỚC 3: XÁC MINH HAI KHÓA CHUNG & DẪN XUẤT HKDF
    assert k_alice == k_bob, "Lỗi: Hai bên không cùng giá trị bí mật chung!"
    key_alice = derive_key(k_alice, RFC_3526_P)
    key_bob = derive_key(k_bob, RFC_3526_P)
    assert key_alice == key_bob, "Lỗi: Khóa AES dẫn xuất không trùng khớp!"

    # BƯỚC 4: MÃ HÓA PHÍA ALICE
    with open(file_src, "rb") as f:
        plaintext = f.read()
    aesgcm_alice = AESGCM(key_alice)
    nonce = os.urandom(12)
    ciphertext = aesgcm_alice.encrypt(nonce, plaintext, None)
    with open(file_enc, "wb") as f:
        f.write(nonce + ciphertext)

    # BƯỚC 5: GIẢI MÃ PHÍA BOB
    with open(file_enc, "rb") as f:
        raw_data = f.read()
    rec_nonce = raw_data[:12]
    rec_ciphertext = raw_data[12:]
    aesgcm_bob = AESGCM(key_bob)
    decrypted_data = aesgcm_bob.decrypt(rec_nonce, rec_ciphertext, None)
    with open(file_dec, "wb") as f:
        f.write(decrypted_data)

    # BƯỚC 6: XÁC MINH TOÀN VẸN
    assert decrypted_data == plaintext, "Lỗi: Dữ liệu giải mã không khớp dữ liệu gốc!"
    hash_src = calculate_file_sha256(file_src)
    hash_dec = calculate_file_sha256(file_dec)
    is_identical = (decrypted_data == plaintext) and (hash_src == hash_dec)

    print(f"[*] Thời gian sinh khóa riêng ngẫu nhiên:   {t_keygen:.6f} giây")
    print(f"[*] Thời gian trao đổi & tính toán số học DH: {t_dh_compute:.6f} giây")
    print(f"[✓] Khóa AES-256 từ HKDF-SHA-256 (32 bytes): {key_alice.hex()[:32]}...")
    print(f"[✓] Tệp mã hóa tạo thành:                   {file_enc} ({len(raw_data)} bytes)")
    print(f"[✓] SHA-256 tệp gốc ban đầu:                {hash_src}")
    print(f"[✓] SHA-256 tệp khôi phục:                  {hash_dec}")
    print(f"[✓] Xác minh tính toàn vẹn (Byte-level):    {'TRÙNG KHỚP 100%' if is_identical else 'SAI LỆCH'}\n")


def menu_mitm_simulation():
    print("\n" + "="*68)
    print("--- 3. MÔ PHỎNG TẤN CÔNG Man-In-The-Middle (MITM) VÀ CƠ CHẾ PHÒNG CHỐNG BẰNG CHỮ KÝ SỐ ---")
    print("="*68)
    p, g = RFC_3526_P, RFC_3526_G
    a = secrets.randbelow(p - 3) + 2
    b = secrets.randbelow(p - 3) + 2
    e = secrets.randbelow(p - 3) + 2

    alice = DiffieHellmanEntity(p, g, private_key=a)
    bob = DiffieHellmanEntity(p, g, private_key=b)
    eve = DiffieHellmanEntity(p, g, private_key=e)

    A = alice.generate_public_key()
    B = bob.generate_public_key()
    E = eve.generate_public_key()

    # =========================================================================
    # KỊCH BẢN 1: GIAO THỨC DH NGUYÊN BẢN (KHÔNG CÓ XÁC THỰC)
    # =========================================================================
    print("\n>>> KỊCH BẢN 1: GIAO THỨC DH NGUYÊN BẢN (KHÔNG CÓ XÁC THỰC) <<<")
    print("[*] 1. Alice gửi A -> Eve chặn bắt và gửi E cho Bob.")
    print("[*] 2. Bob gửi B   -> Eve chặn bắt và gửi E cho Alice.")

    k_alice = alice.compute_shared_secret(E)
    k_eve_alice = eve.compute_shared_secret(A)
    k_bob = bob.compute_shared_secret(E)
    k_eve_bob = eve.compute_shared_secret(B)

    key_alice_eve = derive_key(k_alice, p)
    key_eve_bob = derive_key(k_eve_bob, p)

    msg_alice = "Chuyển khoản 10 triệu đồng cho Bob".encode("utf-8")
    nonce1 = os.urandom(12)
    cipher_alice = AESGCM(key_alice_eve).encrypt(nonce1, msg_alice, None)

    eve_decrypted = AESGCM(key_alice_eve).decrypt(nonce1, cipher_alice, None).decode("utf-8")
    tampered_msg = "Chuyển khoản 100 triệu đồng vào tài khoản của Eve".encode("utf-8")
    nonce2 = os.urandom(12)
    cipher_eve_to_bob = AESGCM(key_eve_bob).encrypt(nonce2, tampered_msg, None)
    bob_decrypted = AESGCM(key_eve_bob).decrypt(nonce2, cipher_eve_to_bob, None).decode("utf-8")

    assert eve_decrypted.encode("utf-8") == msg_alice
    assert bob_decrypted.encode("utf-8") == tampered_msg
    assert bob_decrypted.encode("utf-8") != msg_alice

    print(f"  [Alice] Gửi: \"{msg_alice.decode('utf-8')}\"")
    print(f"  [Eve]   Đánh chặn & sửa thành: \"{tampered_msg.decode('utf-8')}\"")
    print(f"  [Bob]   Giải mã nhận được: \"{bob_decrypted}\"")
    print("  [!] KẾT QUẢ : Tấn công MITM THÀNH CÔNG do thiếu xác thực.")

    # =========================================================================
    # KỊCH BẢN 2: PHÒNG CHỐNG BẰNG CHỮ KÝ SỐ (AUTHENTICATED DH)
    # =========================================================================
    print("\n>>> KỊCH BẢN 2: PHÒNG CHỐNG BẰNG CHỮ KÝ SỐ (AUTHENTICATED DH) <<<")
    print("[*] Alice và Bob tạo cặp khóa ký số dài hạn (Ed25519) đã được định danh.")
    
    alice_sign_priv = ed25519.Ed25519PrivateKey.generate()
    alice_verify_pub = alice_sign_priv.public_key()
    
    bob_sign_priv = ed25519.Ed25519PrivateKey.generate()
    bob_verify_pub = bob_sign_priv.public_key()

    A_bytes = A.to_bytes((A.bit_length() + 7) // 8, "big")
    sig_A = alice_sign_priv.sign(A_bytes)
    print(f"  [Alice] Tạo khóa DH A và đính kèm Chữ ký số: {sig_A.hex()[:16]}...")

    E_bytes = E.to_bytes((E.bit_length() + 7) // 8, "big")
    print("  [Eve]   Chặn bắt gói tin, tráo khóa A bằng E và chuyển tiếp cho Bob...")

    print("  [Bob]   Nhận gói tin, kiểm tra tính hợp lệ của chữ ký trước khi bắt tay...")
    try:
        alice_verify_pub.verify(sig_A, E_bytes)
        print("  [Bob]   Xác minh thành công (Bất thường!).")
    except InvalidSignature:
        print("  [Bob]   CẢNH BÁO AN NINH: Chữ ký số KHÔNG HỢP LỆ! Khóa công khai đã bị can thiệp.")
        print("  [Bob]   HỦY BỎ PHIÊN KẾT NỐI NGAY LẬP TỨC")
        print("  [✓] KẾT QUẢ KỊCH BẢN 2: PHÒNG CHỐNG MITM THÀNH CÔNG NHỜ CHỮ KÝ SỐ.\n")


def menu_test_suite():
    print("\n" + "="*65)
    print("--- 4. BỘ KIỂM THỬ ĐỐI CHUẨN CHI TIẾT TỪNG ĐẠI LƯỢNG (3 CA) ---")
    print("="*65)
    test_cases = [
        ("TC01: Số nhỏ minh họa", 23, 5, 6, 15),
        ("TC02: Tham số 64-bit chức năng", 18446744073709551557, 5, 987654321, 123456789),
        ("TC03: RFC 3526 MODP Group 14", RFC_3526_P, RFC_3526_G, 10**100, 10**100 + 7)
    ]
    
    overall_passed = True
    
    for tc_id, p_val, g_val, a_val, b_val in test_cases:
        print(f"[*] Đang thực thi {tc_id} (Độ dài p: {p_val.bit_length()} bits)...")
        
        ent_a = DiffieHellmanEntity(p_val, g_val, private_key=a_val)
        ent_b = DiffieHellmanEntity(p_val, g_val, private_key=b_val)
        
        my_A = ent_a.generate_public_key()
        my_B = ent_b.generate_public_key()
        my_KA = ent_a.compute_shared_secret(my_B)
        my_KB = ent_b.compute_shared_secret(my_A)
        
        ref_A = pow(g_val, a_val, p_val)
        ref_B = pow(g_val, b_val, p_val)
        ref_KA = pow(my_B, a_val, p_val)
        ref_KB = pow(my_A, b_val, p_val)
        
        chk_A = (my_A == ref_A)
        chk_B = (my_B == ref_B)
        chk_KA = (my_KA == ref_KA)
        chk_KB = (my_KB == ref_KB)
        chk_equal = (my_KA == my_KB)
        
        all_passed = chk_A and chk_B and chk_KA and chk_KB and chk_equal
        if not all_passed:
            overall_passed = False
        
        print(f"    - Khóa công khai Alice  [A]: {'PASSED' if chk_A else 'FAILED'} (khớp pow(g, a, p))")
        print(f"    - Khóa công khai Bob    [B]: {'PASSED' if chk_B else 'FAILED'} (khớp pow(g, b, p))")
        print(f"    - Khóa chung phía Alice [K_A]: {'PASSED' if chk_KA else 'FAILED'} (khớp pow(B, a, p))")
        print(f"    - Khóa chung phía Bob   [K_B]: {'PASSED' if chk_KB else 'FAILED'} (khớp pow(A, b, p))")
        print(f"    - Tính nhất quán khóa [K_A == K_B]: {'PASSED' if chk_equal else 'FAILED'}")
        print(f"    ==> KẾT QUẢ {tc_id}: [{'PASSED' if all_passed else 'FAILED'}]\n")

    if overall_passed:
        print("=> TẤT CẢ 3/3 CA KIỂM THỬ ĐỀU ĐẠT CHUẨN [PASSED] ĐỐI CHIẾU 100%.\n")
    else:
        print("[!] CẢNH BÁO: CÓ CA KIỂM THỬ THẤT BẠI [FAILED]. CẦN KIỂM TRA LẠI THUẬT TOÁN.\n")


def main():
    while True:
        print("="*50)
        print("   HỆ THỐNG DEMO TRAO ĐỔI KHÓA DIFFIE-HELLMAN")
        print("="*50)
        print("1. Demo bộ số nhỏ minh họa")
        print("2. Demo tham số chuẩn 2048-bit & Mã hóa tệp")
        print("3. Minh họa tấn công Người đứng giữa")
        print("4. Chạy bộ kiểm thử đối chiếu")
        print("0. Thoát chương trình")
        choice = input("Nhập lựa chọn (0-4): ").strip()
        
        if choice == "1":
            menu_small_number()
        elif choice == "2":
            menu_file_encryption()
        elif choice == "3":
            menu_mitm_simulation()
        elif choice == "4":
            menu_test_suite()
        elif choice == "0":
            print("Đã thoát chương trình.")
            sys.exit(0)
        else:
            print("[!] Lựa chọn không hợp lệ. Vui lòng nhập lại.\n")


if __name__ == "__main__":
    main()