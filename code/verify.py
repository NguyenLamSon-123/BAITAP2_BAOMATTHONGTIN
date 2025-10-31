# ==========================================
# verify_sign.py
# Kiểm tra chữ ký số trong file PDF (tương thích nhiều phiên bản pyHanko)
# Thực hiện: NGUYỄN LAM SƠN
# ==========================================

import os
import re
import hashlib
import datetime
from datetime import timezone, timedelta
from typing import Any, Optional, Tuple

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko_certvalidator import ValidationContext
from pyhanko.keys import load_cert_from_pemder

# validation module (dùng làm fallback)
from pyhanko.sign import validation

# === Cấu hình đường dẫn (chỉnh theo máy bạn) ===
PDF_PATH = r"D:\BaomatTT\pdf\signed.pdf"
CERT_PEM = r"D:\BaomatTT\key\certificate.pem"
LOG_FILE = r"D:\BaomatTT\pdf\kiemtra.txt"


# ================== HÀM PHỤ TRỢ ==================

def safe_print(msg: str):
    """In ra console không lỗi font."""
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("utf-8", errors="ignore").decode("utf-8"))


def log(msg: str):
    """In ra console và ghi vào file log."""
    safe_print(msg)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8", errors="ignore") as f:
        f.write(msg + "\n")


def format_fp(fp: Optional[Any]) -> str:
    """Định dạng fingerprint cho dễ đọc."""
    if fp is None:
        return "N/A"
    if isinstance(fp, (bytes, bytearray)):
        h = fp.hex().upper()
    else:
        s = str(fp)
        h = re.sub(r"[^0-9A-Fa-f]", "", s).upper()
        if not h:
            return s
    return " ".join(h[i:i + 2] for i in range(0, len(h), 2))


def compute_sha256_range(pdf_bytes: bytes, byte_range):
    """Tính hash SHA256 trên vùng ByteRange (2 phần)."""
    try:
        br = [int(x) for x in byte_range]
        part1 = pdf_bytes[br[0]: br[0] + br[1]]
        part2 = pdf_bytes[br[2]: br[2] + br[3]]
        return hashlib.sha256(part1 + part2).hexdigest()
    except Exception as e:
        return f"Lỗi khi tính hash: {e}"


def get_first_attr(obj: Any, *names):
    """Truy cập attribute hoặc key đầu tiên hợp lệ trong object."""
    if obj is None:
        return None
    for n in names:
        try:
            if hasattr(obj, n):
                return getattr(obj, n)
        except Exception:
            pass
        try:
            if isinstance(obj, dict) and n in obj:
                return obj[n]
        except Exception:
            pass
    return None


def try_validate_signature(sig_obj, trust_ctx) -> Tuple[Optional[Any], Optional[str]]:
    """
    Thử nhiều cách để validate signature object, tương thích nhiều phiên bản pyHanko.
    Trả về (result_object_or_None, error_message_or_None)
    """
    # 1) Nếu đối tượng có method compute_digital_signature_status -> ưu tiên
    try:
        if hasattr(sig_obj, "compute_digital_signature_status"):
            try:
                res = sig_obj.compute_digital_signature_status(validation_context=trust_ctx)
                return res, None
            except TypeError:
                # try positional
                try:
                    res = sig_obj.compute_digital_signature_status(trust_ctx)
                    return res, None
                except Exception as e:
                    last = e
            except Exception as e:
                return None, f"Lỗi khi gọi compute_digital_signature_status: {e}"
    except Exception:
        pass

    # 2) Thử dùng validation.validate_pdf_signature với các biến thể tham số
    attempts = [
        {"kw": {"validation_context": trust_ctx}},
        {"kw": {"vc": trust_ctx}},
        {"pos": (trust_ctx,)},
        {"kw": {}},  # no context
    ]
    last_err = None
    for attempt in attempts:
        try:
            if "kw" in attempt:
                res = validation.validate_pdf_signature(sig_obj, **attempt["kw"])
            else:
                res = validation.validate_pdf_signature(sig_obj, *attempt["pos"])
            return res, None
        except TypeError as te:
            last_err = te
            continue
        except Exception as e:
            # Khi validate trả lỗi khác (network, ocsp), vẫn trả về lỗi chi tiết
            return None, f"Lỗi khi gọi validate_pdf_signature: {e}"

    return None, f"Tất cả cách gọi validate_pdf_signature đều thất bại. LastError: {repr(last_err)}"


# ================== CHƯƠNG TRÌNH CHÍNH ==================

def main():
    # Xóa file log cũ
    try:
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
    except Exception:
        pass

    log("=== NGUYỄN LAM SƠN - KIỂM TRA CHỮ KÝ SỐ PDF ===")
    log(f"THỜI GIAN KIỂM TRA: {datetime.datetime.now()}")
    log(f"TỆP PDF: {PDF_PATH}")
    log("=" * 65)

    # === Tạo ValidationContext ===
    try:
        if os.path.exists(CERT_PEM):
            cert_root = load_cert_from_pemder(CERT_PEM)
            trust_ctx = ValidationContext(trust_roots=[cert_root], allow_fetching=True)
            log("- Đã nạp chứng thư gốc từ PEM.")
        else:
            trust_ctx = ValidationContext(trust_roots=None, allow_fetching=True)
            log("- Không có PEM tin cậy, cho phép OCSP/CRL online.")
    except Exception as e:
        log(f"⚠️ Lỗi khi đọc chứng thư: {e}")
        trust_ctx = ValidationContext(trust_roots=None, allow_fetching=True)

    if not os.path.exists(PDF_PATH):
        log(f"❌ File PDF không tồn tại: {PDF_PATH}")
        return

    try:
        with open(PDF_PATH, "rb") as fh:
            reader = PdfFileReader(fh)
            signatures = list(reader.embedded_signatures)
            if not signatures:
                log("❌ Không tìm thấy chữ ký trong tài liệu.")
                return

            sig = signatures[0]  # lấy chữ ký đầu tiên
            log(f"- Phát hiện signature field: {sig.field_name or 'Signature'}")

            # Lấy object chữ ký nội bộ nếu có
            sig_obj = getattr(sig, "sig_object", None)
            if sig_obj is None:
                try:
                    sig_obj = sig.get_signature()
                except Exception:
                    sig_obj = None

            # Lấy ByteRange và /Contents (nỗ lực an toàn)
            try:
                low = getattr(sig_obj, "sig_object", sig_obj) or sig_obj
                br = low.get("/ByteRange") if low is not None else None
                contents = low.get("/Contents") if low is not None else None
                br_list = [int(x) for x in br] if br else None
                log(f"- ByteRange: {br_list if br_list else 'Không có'}")
                clen = len(contents) if contents is not None else "N/A"
                log(f"- /Contents length: {clen} bytes")
            except Exception as e:
                log(f"⚠️ Không đọc được /ByteRange hoặc /Contents: {e}")
                br_list = None

            # Tính lại SHA256
            fh.seek(0)
            pdf_data = fh.read()
            if br_list:
                calc_hash = compute_sha256_range(pdf_data, br_list)
                log(f"- Hash SHA256 theo ByteRange: {calc_hash}")
            else:
                calc_hash = None
                log("- Không tính hash (thiếu ByteRange).")

            # === Thực hiện validate (linh hoạt) ===
            log("- Bắt đầu xác thực chữ ký (pyHanko) - thử nhiều phương thức...")
            result, err = try_validate_signature(sig, trust_ctx)
            if err:
                log(f"⚠️ Lỗi/ghi chú khi validate: {err}")
            if result is None:
                log("❌ Không nhận được kết quả xác thực. Dừng.")
                return

            # Chi tiết kết quả (nếu có)
            try:
                pretty = getattr(result, "pretty_print_details", None)
                if pretty:
                    details = pretty()
                else:
                    details = str(result)
                log("\n--- Chi tiết validate (pyHanko) ---")
                for line in str(details).splitlines():
                    log("  " + line)
                log("-----------------------------------\n")
            except Exception:
                pass

            # Thông tin chứng thư người ký
            signer_cert = get_first_attr(result, "signer_cert", "signing_cert", "signing_certificate")
            log("Thông tin chứng thư người ký:")
            if signer_cert:
                subj = get_first_attr(signer_cert, "subject")
                readable = getattr(subj, "human_friendly", str(subj))
                fp1 = get_first_attr(signer_cert, "sha1_fingerprint") or get_first_attr(signer_cert, "sha1")
                fp2 = get_first_attr(signer_cert, "sha256_fingerprint") or get_first_attr(signer_cert, "sha256")
                log(f" - Chủ thể: {readable}")
                log(f" - SHA1 Fingerprint: {format_fp(fp1)}")
                log(f" - SHA256 Fingerprint: {format_fp(fp2)}")
            else:
                log(" - ⚠️ Không thể trích xuất chứng thư người ký.")

            # Kiểm tra chain/trust
            trusted = get_first_attr(result, "trusted")
            valid = get_first_attr(result, "valid")
            if trusted is True:
                log("- Chuỗi chứng thư: ✅ Được tin cậy (CA hợp lệ).")
            elif valid:
                log("- Chuỗi chứng thư: ⚠️ Hợp lệ nhưng chưa có CA gốc.")
            else:
                log("- Chuỗi chứng thư: ❌ Không hợp lệ hoặc không xác định.")

            # OCSP/CRL
            rev = get_first_attr(result, "revinfo_validity") or get_first_attr(result, "revinfo_summary")
            if rev:
                log(f"- Trạng thái thu hồi (OCSP/CRL): {rev}")
            else:
                log("- Không có dữ liệu OCSP/CRL.")

            # Thời gian ký
            stime = get_first_attr(result, "signing_time", "signer_reported_dt", "signer_time")
            if stime:
                try:
                    tzvn = timezone(timedelta(hours=7))
                    vn_time = stime.astimezone(tzvn)
                    log(f"- Thời gian ký (UTC): {stime}  → Giờ VN: {vn_time}")
                except Exception:
                    log(f"- Thời gian ký: {stime}")
            else:
                log("- Không tìm thấy timestamp trong chữ ký.")

            # Kiểm tra chỉnh sửa sau khi ký
            mod_level = get_first_attr(result, "modification_level")
            mod_str = str(mod_level)
            try:
                if mod_level is not None and (("NONE" in mod_str) or (mod_level == ModificationLevel.NONE)):
                    log("- Kiểm tra chỉnh sửa: ✅ Không có thay đổi sau khi ký.")
                elif mod_level is not None and (("FORM_FILLING" in mod_str) or (mod_level == ModificationLevel.FORM_FILLING)):
                    log("- Kiểm tra chỉnh sửa: ⚠️ Có điền form sau khi ký.")
                else:
                    log("- Kiểm tra chỉnh sửa: ❌ File có thể đã bị thay đổi hoặc không xác định rõ.")
            except Exception:
                log(f"- Kiểm tra chỉnh sửa: (không xác định) mod_level={mod_level}")

            # Tổng kết
            log("\n=== KẾT LUẬN CHUNG ===")
            if valid:
                log("Kết quả: ✅ CHỮ KÝ HỢP LỆ — FILE NGUYÊN VẸN.")
            else:
                log("Kết quả: ❌ CHỮ KÝ KHÔNG HỢP LỆ HOẶC FILE BỊ CAN THIỆP.")

    except Exception as e:
        log(f"❌ Lỗi xử lý PDF: {e}")

    log(f"\nHoàn tất. Báo cáo lưu tại: {os.path.abspath(LOG_FILE)}")


# =========================================================
if __name__ == "__main__":
    main()
