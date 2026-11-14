"""
Module: core_dh.py
Cài đặt thuật toán số học lõi và lớp trao đổi khóa Diffie-Hellman thuần túy.
TUYỆT ĐỐI KHÔNG SỬ DỤNG BẤT KỲ THƯ VIỆN NÀO (0 IMPORT).
"""

def power_mod(base: int, exponent: int, modulus: int, verbose: bool = False) -> int:
    """
    Thuật toán lũy thừa modulo nhanh (Square-and-Multiply - LSB first).
    Độ phức tạp thời gian: O(log(exponent))
    
    Ràng buộc đầu vào:
    - base, exponent, modulus bắt buộc phải là số nguyên.
    - modulus > 1.
    - exponent >= 0 (chặn số mũ âm).
    """
    if not isinstance(base, int) or not isinstance(exponent, int) or not isinstance(modulus, int):
        raise TypeError("Tất cả các tham số (base, exponent, modulus) phải là số nguyên.")
        
    if modulus <= 1:
        raise ValueError("Modulus (p) phải là số nguyên lớn hơn 1.")
        
    if exponent < 0:
        raise ValueError("Số mũ (exponent) phải là số nguyên không âm.")

    result = 1
    base = base % modulus
    exp = exponent
    step = 0

    if verbose:
        print(f"[*] Khởi tạo: Base = {base}, Exp = {exp} (nhị phân: {bin(exp)[2:]}), Mod = {modulus}")

    while exp > 0:
        step += 1
        current_bit = exp & 1
        if verbose:
            print(f"  - Bước {step}: Bit hiện tại = {current_bit}", end="")
            
        if current_bit == 1:
            result = (result * base) % modulus
            if verbose:
                print(f" | Multiply: result = {result}", end="")
        elif verbose:
            print(f" | Multiply: bỏ qua", end="")

        exp >>= 1
        base = (base * base) % modulus
        if verbose:
            print(f" | Square: base mới = {base}")

    return result


class DiffieHellmanEntity:
    """
    Thực thể trao đổi khóa Diffie-Hellman phục vụ môi trường học thuật.
    Lưu ý:
    - Chương trình giả định bộ tham số (p, g) đã được thẩm định tính nguyên tố 
      và tính hợp lệ của phần tử sinh từ trước (ví dụ theo chuẩn RFC 3526).
    - Các bước kiểm tra dưới đây chỉ là kiểm tra phạm vi cơ bản (Range Validation),
      chưa bao gồm kiểm tra nhóm con chuyên sâu (Subgroup Validation).
    """
    def __init__(self, p: int, g: int, private_key: int):
        if not isinstance(p, int) or not isinstance(g, int) or not isinstance(private_key, int):
            raise TypeError("Các tham số p, g và private_key bắt buộc phải là số nguyên.")

        # 1. Kiểm tra phạm vi cơ bản của tham số miền
        if p <= 2:
            raise ValueError("Tham số p phải là số nguyên lớn hơn 2 (cần bộ tham số nguyên tố xác nhận trước).")
        if not (2 <= g < p):
            raise ValueError(f"Phần tử sinh g phải nằm trong phạm vi cơ bản [2, p - 1].")
            
        # 2. Kiểm tra phạm vi khóa riêng
        if not (2 <= private_key <= p - 2):
            raise ValueError(f"Khóa riêng phải nằm trong khoảng an toàn cơ bản [2, p - 2].")

        self.p = p
        self.g = g
        self.private_key = private_key
        self.public_key = None
        self.shared_secret = None

    def generate_public_key(self, verbose: bool = False) -> int:
        """Sinh khóa công khai: Public Key = g^(private_key) mod p"""
        self.public_key = power_mod(self.g, self.private_key, self.p, verbose=verbose)
        return self.public_key

    def compute_shared_secret(self, peer_public_key: int, verbose: bool = False) -> int:
        """
        Kiểm tra phạm vi khóa công khai đối tác và tính bí mật chung:
        Shared Secret = (peer_public_key)^(private_key) mod p
        """
        if not isinstance(peer_public_key, int):
            raise TypeError("Khóa công khai nhận được phải là số nguyên.")
            
        if not (2 <= peer_public_key <= self.p - 2):
            raise ValueError(f"Khóa công khai nhận được nằm ngoài phạm vi cho phép [2, p - 2]: {peer_public_key}")

        self.shared_secret = power_mod(peer_public_key, self.private_key, self.p, verbose=verbose)
        return self.shared_secret