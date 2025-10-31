# ==========================================
# sign_pdf.py - Ký PDF bằng pyHanko
# ==========================================
import os
from datetime import datetime
from pyhanko.sign import signers, fields
from pyhanko.stamp.text import TextStampStyle
from pyhanko.pdf_utils import images
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.pdf_utils.layout import SimpleBoxLayoutRule, AxisAlignment, Margins
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigFieldSpec
from pypdf import PdfReader, PdfWriter

# === Cấu hình đường dẫn ===
BASE_DIR = r"D:\BaomatTT"
PDF_ORIG = os.path.join(BASE_DIR, "pdf", "original.pdf")
PDF_CLEAN = os.path.join(BASE_DIR, "pdf", "original_clean.pdf")
PDF_SIGNED = os.path.join(BASE_DIR, "pdf", "signed.pdf")
KEY_FILE = os.path.join(BASE_DIR, "key", "private-key.pem")
CERT_FILE = os.path.join(BASE_DIR, "key", "certificate.pem")
SIG_IMG = os.path.join(BASE_DIR, "chuky", "chuky.png")

# === Bước 1: Làm sạch PDF hybrid ===
print("🧹 Đang làm sạch PDF hybrid...")

reader = PdfReader(PDF_ORIG)
writer_clean = PdfWriter()
for page in reader.pages:
    writer_clean.add_page(page)

with open(PDF_CLEAN, "wb") as f:
    writer_clean.write(f)

print(f"✅ Đã tạo file sạch: {PDF_CLEAN}")

# === Bước 2: Tạo signer ===
signer = signers.SimpleSigner.load(KEY_FILE, CERT_FILE, key_passphrase=None)

# === Bước 3: Ký file ===
with open(PDF_CLEAN, "rb") as inf:
    writer = IncrementalPdfFileWriter(inf)

    # Trang cuối
    num_pages = len(list(writer.root["/Pages"].get("/Kids")))
    target_page = num_pages - 1

    # Thêm field chữ ký
    fields.append_signature_field(
        writer,
        SigFieldSpec(
            sig_field_name="FooterSig",
            box=(50, 30, 550, 100),
            on_page=target_page
        )
    )

    # Ảnh chữ ký
    # --- Tương thích mọi bản pyHanko ---
    try:
        background_img = images.PdfImage.open(SIG_IMG)
    except AttributeError:
        background_img = images.PdfImage(SIG_IMG)

    # Bố cục ảnh và chữ
    bg_layout = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MID,
        margins=Margins(right=20)
    )
    text_layout = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MID,
        margins=Margins(left=150)
    )

    text_style = TextBoxStyle(font_size=13)
    ngay_ky = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    stamp_text = (
        "Nguyen Lam SOn"
        "\nSDT: 0123456789"
        "\nMSV: K225480106076"
        f"\nNgày ký: {ngay_ky}"
    )

    stamp_style = TextStampStyle(
        stamp_text=stamp_text,
        background=background_img,
        background_layout=bg_layout,
        inner_content_layout=text_layout,
        text_box_style=text_style,
        border_width=1,
        background_opacity=1.0,
    )

    meta = signers.PdfSignatureMetadata(
        field_name="FooterSig",
        reason="Chu ky so",
        location="Thái Nguyên",
        md_algorithm="sha256",
    )

    pdf_signer = signers.PdfSigner(
        signature_meta=meta,
        signer=signer,
        stamp_style=stamp_style
    )

    with open(PDF_SIGNED, "wb") as outf:
        pdf_signer.sign_pdf(writer, output=outf)

print(f"✅ Đã ký PDF thành công: {PDF_SIGNED}")
