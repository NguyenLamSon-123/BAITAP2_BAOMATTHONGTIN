# tamper_pdf.py
# Tạo bản tampered từ signed.pdf
# Mặc định: sửa 1 byte ở giữa (chắc chắn làm hỏng chữ ký)
# Nếu gọi với tham số "append" thì chèn 1 dòng comment ở cuối.
#
# Usage:
#   python tamper_pdf.py        # sửa 1 byte giữa file
#   python tamper_pdf.py append # chèn dòng comment vào cuối file

import sys
import os

BASE_DIR = r"D:\BaomatTT"
SIGNED_PDF = os.path.join(BASE_DIR, "pdf", "signed.pdf")
TAMPERED_PDF = os.path.join(BASE_DIR, "pdf", "tampered.pdf")

def tamper_modify_byte(src_path, dst_path):
    with open(src_path, "rb") as f:
        b = bytearray(f.read())
    if len(b) == 0:
        raise RuntimeError("File rỗng")
    # sửa 1 byte ở tâm file (thay đổi giá trị, không out-of-range)
    idx = len(b) // 2
    b[idx] = (b[idx] + 1) % 256
    with open(dst_path, "wb") as f:
        f.write(b)

def tamper_append_comment(src_path, dst_path):
    with open(src_path, "ab") as f:
        f.write(b"\n% Tampered by NGUYEN LAM SON\n")
    # nếu muốn tạo file mới (không ghi đè), copy + append:
    # import shutil
    # shutil.copy(src_path, dst_path)
    # with open(dst_path, "ab") as f:
    #     f.write(b"\n% Tampered by NGUYEN LAM SON\n")

def main():
    if not os.path.exists(SIGNED_PDF):
        print("❌ Không tìm thấy:", SIGNED_PDF)
        return

    mode = ""
    if len(sys.argv) > 1 and sys.argv[1].lower() == "append":
        mode = "append"

    # đảm bảo thư mục tồn tại
    os.makedirs(os.path.dirname(TAMPERED_PDF), exist_ok=True)

    if mode == "append":
        # tạo bản copy rồi append comment để dễ kiểm tra
        import shutil
        shutil.copyfile(SIGNED_PDF, TAMPERED_PDF)
        with open(TAMPERED_PDF, "ab") as f:
            f.write(b"\n% Tampered by NGUYEN LAM SON\n")
        print("✅ Đã tạo tampered (append) tại:", TAMPERED_PDF)
    else:
        # sửa 1 byte giữa, ghi file mới
        with open(SIGNED_PDF, "rb") as f:
            data = bytearray(f.read())
        if len(data) == 0:
            print("❌ File rỗng, không thể tamper")
            return
        idx = len(data) // 2
        data[idx] = (data[idx] + 1) % 256
        with open(TAMPERED_PDF, "wb") as f:
            f.write(data)
        print("✅ Đã tạo tampered (modified byte) tại:", TAMPERED_PDF)
        print("ℹ️ This change very likely invalidates the signature.")

if __name__ == "__main__":
    main()
