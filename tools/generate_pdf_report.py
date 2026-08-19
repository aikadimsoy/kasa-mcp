# tools/generate_pdf_report.py

"""
KASA - Profesyonel PDF Güvenlik ve Mimari Raporu Üreteci
Matplotlib grafiklerini ve ReportLab Platypus mimarisini kullanarak
yüksek kaliteli, görsel şemalı ve tablolu bir PDF raporu üretir.
"""

import os
import sys
import tempfile
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    PageBreak,
    HRFlowable,
)


# Türkçe not: Buradaki "rakip karşılaştırma grafiği" KALDIRILDI (2026-08-19).
#
# Kaldırılma sebebi ölçülmüş bir kusurdur: grafiğin barları elle yazılmış
# sayılardan üretiliyordu — kasa=[100,100,100,100,100], mem0=[25,30,0,20,15],
# letta=[35,20,0,15,15], zep=[20,15,0,15,10]. Mem0, Letta ve Zep hiç kurulmadı,
# hiç koşturulmadı, hiç ölçülmedi. Yani grafik bir ölçüm değil, bir tahmindi;
# ama grafik biçiminde sunulunca ölçüm gibi okunuyordu.
#
# Bu üçü gerçek ticari ürünlerdir. Ölçülmemiş sayılarla kamuya açık bir
# kötüleme grafiği yayımlamak hem projenin kendi kanıt disiplinine aykırıdır
# hem de gereksiz bir hukuki risktir.
#
# Yerine gelen: kaynak gösterilen, sayısız bir YETENEK tablosu (build_pdf
# içinde). Bir rakip hakkında bir hücre ancak o ürünün kendi dokümantasyonuna
# atıfla doldurulur; atıf yoksa hücre "bilinmiyor" olur.


def generate_architecture_chart(output_path: str):
    """KASA Yaşam Döngüsü ve Reference Monitor akış şeması."""
    fig, ax = plt.subplots(figsize=(10, 4.2), dpi=300)
    ax.axis("off")

    # Kutu stilleri
    bbox_agent = dict(boxstyle="round,pad=0.6", facecolor="#EBF5FB", edgecolor="#2980B9", lw=2)
    bbox_ref = dict(boxstyle="round,pad=0.8", facecolor="#FEF9E7", edgecolor="#F39C12", lw=2.5)
    bbox_vault = dict(boxstyle="round,pad=0.6", facecolor="#E8F8F5", edgecolor="#27AE60", lw=2)
    bbox_quarantine = dict(boxstyle="round,pad=0.6", facecolor="#FDEDEC", edgecolor="#C0392B", lw=2)
    bbox_audit = dict(boxstyle="round,pad=0.6", facecolor="#F4ECF7", edgecolor="#8E44AD", lw=2)

    # Bileşenler
    ax.text(0.12, 0.75, "Dış AI Ajanı\n(LangChain/Claude)", ha="center", va="center", fontsize=9, fontweight="bold", bbox=bbox_agent)
    ax.text(0.50, 0.75, "KASA REFERENCE MONITOR\n[gate.py + Token Resolver]\n• İzin Tablosu (Deny-by-default)\n• Karantina Süzgeci\n• Egress Ağ Kalkanı", ha="center", va="center", fontsize=9, fontweight="bold", color="#7D6608", bbox=bbox_ref)
    
    ax.text(0.88, 0.85, "CANLI VAULT (Diskte)\n• AES-256-GCM Şifreli\n• HMAC Kör İndeks", ha="center", va="center", fontsize=9, fontweight="bold", color="#196F3D", bbox=bbox_vault)
    ax.text(0.88, 0.45, "KARANTİNA DEPOSU\n• İzole Zararlı Komutlar\n• Canlı Hafızayı Kirletmez", ha="center", va="center", fontsize=9, fontweight="bold", color="#922B21", bbox=bbox_quarantine)
    
    ax.text(0.50, 0.18, "KRİPTOGRAFİK ADLİ İZ (Audit Chain)\n• Ed25519 Dijital İmza • Merkle Kökleri (Tamper-Proof)", ha="center", va="center", fontsize=9, fontweight="bold", color="#5B2C6F", bbox=bbox_audit)

    # Oklar
    ax.annotate("", xy=(0.33, 0.75), xytext=(0.24, 0.75), arrowprops=dict(arrowstyle="->", lw=2, color="#2C3E50"))
    ax.annotate("", xy=(0.77, 0.85), xytext=(0.67, 0.78), arrowprops=dict(arrowstyle="->", lw=2, color="#27AE60"))
    ax.annotate("", xy=(0.77, 0.45), xytext=(0.67, 0.72), arrowprops=dict(arrowstyle="->", lw=2, color="#C0392B"))
    ax.annotate("", xy=(0.50, 0.28), xytext=(0.50, 0.55), arrowprops=dict(arrowstyle="->", lw=2, color="#8E44AD"))

    ax.text(0.285, 0.78, "MCP Çağrısı", ha="center", fontsize=8, color="#566573")
    ax.text(0.72, 0.85, "İzinli/Temiz", ha="center", fontsize=8, color="#27AE60", fontweight="bold")
    ax.text(0.72, 0.55, "Enjeksiyon", ha="center", fontsize=8, color="#C0392B", fontweight="bold")
    ax.text(0.55, 0.42, "Her Eylemi Mühürle", ha="center", fontsize=8, color="#8E44AD")

    plt.tight_layout()
    plt.savefig(output_path, format="png")
    plt.close()


def build_pdf_report(pdf_filename: str):
    """Tüm bölümleri ve görselleri içeren PDF raporu oluşturur."""
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )

    styles = getSampleStyleSheet()

    # Özel Tipografi Stilleri
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0E6655"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#5D6D7E"),
        spaceAfter=15,
    )
    h2_style = ParagraphStyle(
        "Heading2Custom",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1A5276"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#2C3E50"),
        spaceAfter=8,
    )
    callout_style = ParagraphStyle(
        "Callout",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#196F3D"),
    )

    story = []

    # Geçici grafik dosyaları
    with tempfile.TemporaryDirectory() as tmp_dir:
        chart_arch_path = os.path.join(tmp_dir, "arch.png")

        generate_architecture_chart(chart_arch_path)

        # -------------------------------------------------------------
        # BAŞLIK & YÖNETİCİ ÖZETİ
        # -------------------------------------------------------------
        story.append(Paragraph("KASA: Sovereign AI Memory & Security Layer", title_style))
        story.append(Paragraph("Yerel-Öncelikli Yapay Zeka Ajan Hafıza Kasası ve Reference Monitor Raporu", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0E6655"), spaceAfter=12))

        summary_box_data = [[
            Paragraph("<b>Özet:</b> KASA, otonom AI ajanları (LangChain, CrewAI, MCP) ile yerel "
                      "veriler/araçlar arasına <b>deterministik bir güvenlik kapısı (Reference "
                      "Monitor)</b> koyan, belirli hafıza hücrelerini şifreleyen (AES-256-GCM) ve "
                      "eylemleri Ed25519 ile mühürleyen yerel-öncelikli (Local-First) bir güvenlik "
                      "katmanıdır. <b>v0.1 — Araştırma Önizlemesi; üretim için değildir.</b><br/><br/>"
                      "<b>Kanıt durumu:</b> 368 otomatik test (367 geçti, 1 xfail) ve 21 kontrollük "
                      "güvenlik tezgâhı (21 PASS) koştu. Bu sayılar <i>uygulamanın davranışını</i> "
                      "doğrular, <i>üretim güvenliğini değil</i>. Tezgâhın 21 kontrolü authz (7), "
                      "kripto (5), tarama (4), denetim izi (3) ve fuzz (2) kategorilerindedir; "
                      "<b>enjeksiyon, hafıza zehirlenmesi ve egress bu tezgâhta ölçülmemiştir</b>. "
                      "Açık bulgular: F-DISTILL (distiller yolunda düz metin), F-POISON, F-IMP, "
                      "F-MCP — ayrıntısı SECURITY.md'de.", callout_style)
        ]]
        summary_table = Table(summary_box_data, colWidths=[18 * cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#E8F8F5")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#A3E4D7")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # ŞEMA: MİMARİ VE ÇALIŞMA AKIŞI
        # -------------------------------------------------------------
        story.append(Paragraph("1. KASA Güvenlik Mimarisi ve Reference Monitor Akışı", h2_style))
        story.append(Paragraph("KASA'nın temel tezi: <i>'Model sınır değildir; karar deterministik kapıda verilir (Model Proposes, Boundary Disposes).'</i> Dışarıdan gelen web direktifleri hafızaya yazılmadan önce yapısal karantina filtresinden geçer.", body_style))
        story.append(Image(chart_arch_path, width=17.5 * cm, height=7.35 * cm))
        story.append(Spacer(1, 10))

        # -------------------------------------------------------------
        # GRAFİK: SEKTÖREL KARŞILAŞTIRMA
        # -------------------------------------------------------------
        story.append(Paragraph("2. Konumlandırma: KASA Nerede Duruyor?", h2_style))
        story.append(Paragraph(
            "<b>Bu bölüm bir karşılaştırma testi değildir.</b> Mem0, Letta ve Zep bu rapor için "
            "kurulmadı, koşturulmadı ve ölçülmedi; dolayısıyla bu ürünlerin güvenlik davranışı "
            "hakkında burada <b>hiçbir ölçüm iddiası yoktur</b>. Aşağıdaki tablo yalnız her projenin "
            "<i>kendi kamuya açık konumlandırmasını</i> yan yana koyar (kanıt seviyesi: DOCUMENTED). "
            "KASA satırındaki hücreler bu makinede ölçülmüştür (kanıt seviyesi: RAN-LIVE) ve ölçüm "
            "komutları docs/REPRODUCE.md'de listelidir.", body_style))

        pos_data = [
            ["Proje", "Kendi tanımladığı kategori", "Bu raporda ölçüldü mü?"],
            ["KASA", "Ajanlar ile veri/araçlar arasında cihaz-yerel yetki kapısı "
                     "(reference monitor) + şifreli hafıza", "Evet — 357 test, 21 kontrol"],
            ["Mem0", "AI ajanları için hafıza altyapısı (memory layer)", "Hayır — ölçülmedi"],
            ["Letta", "Uzun süreli ajanlar için hafıza/durum yönetimi", "Hayır — ölçülmedi"],
            ["Zep", "Zamansal bilgi grafiği tabanlı ajan hafızası", "Hayır — ölçülmedi"],
        ]
        pos_table = Table(pos_data, colWidths=[2.6 * cm, 9.4 * cm, 6.0 * cm])
        pos_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0E6655")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#BDC3C7")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#E8F8F5")),
        ]))
        story.append(pos_table)
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "<i>Neyi göstermez:</i> Bu tablo hiçbir ürünün diğerinden güvenli olduğunu göstermez. "
            "Farklı kategorileri gösterir. Gerçek bir karşılaştırma, üç ürünün de aynı saldırı "
            "korpusuna karşı aynı koşuda ölçülmesini gerektirir; bu yapılmamıştır.", body_style))
        story.append(Spacer(1, 10))

        story.append(PageBreak())

        # -------------------------------------------------------------
        # TABLO: 5 TEMEL TEHDİT VE SAVUNMA MATRİSİ
        # -------------------------------------------------------------
        story.append(Paragraph("3. Tehdit Modeli ve Savunma Matrisi (A1 - A4)", h2_style))
        
        # Türkçe not: "Sonuç" sütunu artık HANGİ KOŞUNUN ölçtüğünü söyler.
        # Eski hâli beş satıra da PASS yazıyordu; oysa 21 kontrollük tezgâh
        # enjeksiyon ve egress'i HİÇ ölçmüyor (kategoriler: authz/kripto/tarama/
        # denetim/fuzz). Ölçülmemiş bir dala PASS yazmak, puanlayıcının önüne
        # hiç girdi gelmemesi demektir.
        table_data = [
            ["Tehdit Alanı", "Saldırı Türü", "KASA'daki mekanizma", "Ölçüm durumu (2026-08-19)"],
            ["A1 - Prompt Injection", "MINJA hafıza zehirlenmesi",
             "Deterministik karantina (_QUARANTINE_PATTERNS)",
             "ÖLÇÜLMEDİ — güvenlik tezgâhında enjeksiyon kontrolü yok. "
             "F-POISON açık (SECURITY.md)."],
            ["A2 - Impersonation", "Sahte agent_id='system'",
             "Token-kimlik çözücü (F-IMP)",
             "ÖLÇÜLDÜ — AUTHZ-C5 PASS (HTTP 403), canlı sunucuya karşı."],
            ["A2 - Data Egress", "Dışarıya anahtar sızdırma",
             "Egress Guard (domain allowlist + regex)",
             "KISMEN — modülün birim testi var; uçtan uca egress ölçümü yok."],
            ["A4 - At-Rest hırsızlık", "SQLite dosyasının çalınması",
             "Hücre bazlı AES-256-GCM + AAD bağlama",
             "KISMEN — CRYPTO-ATREST PASS; ancak F-DISTILL açık: distiller "
             "yolunda profile.value DÜZ METİN yazılıyor."],
            ["A2 - Kayıt tahrifatı", "Denetim izinin silinmesi/değiştirilmesi",
             "Ed25519 imza + hash zinciri",
             "ÖLÇÜLDÜ — AUDIT-TAMPER-MODIFY ve -DELETE PASS."],
        ]

        matrix_table = Table(table_data, colWidths=[3.2 * cm, 3.6 * cm, 4.7 * cm, 6.5 * cm])
        matrix_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A5276")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (-1, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#BDC3C7")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F9F9")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(matrix_table)
        story.append(Spacer(1, 12))

        # -------------------------------------------------------------
        # AÇIK KAYNAK TARAYICI (kasa-scan) & KOD ÖRNEĞİ
        # -------------------------------------------------------------
        story.append(Paragraph("4. Açık Kaynak Güvenlik Tarayıcısı (kasa-scan) & SDK", h2_style))
        story.append(Paragraph("Dünyadaki herhangi bir MCP sunucusunu veya ajan hafızasını tek satırla denetlemek için açık kaynaklı CLI ve GitHub Action geliştirilmiştir:", body_style))

        code_box_data = [[
            Paragraph("<b># 1. Herhangi bir MCP sunucusunu 10 saniyede tara:</b><br/>python -m tools.scanner.cli --url http://127.0.0.1:8000 --lang tr<br/><br/><b># 2. Python ajanına tek satırda bağla:</b><br/>from src.client import KasaClient<br/>kasa = KasaClient(token='bearer_token')<br/>kasa.ingest(source='cli', type='event', content={'task': 'analysis'})", ParagraphStyle("CodeStyle", fontName="Courier", fontSize=8, leading=11, textColor=colors.HexColor("#17202A")))
        ]]
        code_table = Table(code_box_data, colWidths=[18 * cm])
        code_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F2F4F4")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#BDC3C7")),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(code_table)
        story.append(Spacer(1, 12))

        # -------------------------------------------------------------
        # ALT BİLGİ & DOĞRULAMA
        # -------------------------------------------------------------
        story.append(Paragraph("5. Doğrulama ve Test Kanıtı (RAN-LIVE)", h2_style))
        story.append(Paragraph(
            "• <b>Birim ve entegrasyon testleri:</b> 368 test — 367 geçti, 1 xfail "
            "(ölçüm: 2026-08-19, bu ağaç). "
            "(<i>xfail bir geçiş değildir; beklenen başarısızlıktır. Bu yüzden \"%100 PASS\" "
            "denmez.</i>)<br/>"
            "• <b>Güvenlik tezgâhı:</b> 21 kontrol, 21 PASS. Kategoriler: authz 7, kripto 5, "
            "tarama 4, denetim izi 3, fuzz 2. <b>Enjeksiyon, hafıza zehirlenmesi ve egress "
            "kontrolü bu tezgâhta yoktur.</b><br/>"
            "• <b>Tarayıcı (kasa-scan) iki yönlü testi:</b> güvensiz fixture'da FAIL üretir, "
            "uygulanamaz hedefte SKIP verir ve skor basmaz — tests/test_scanner_cli.py (14 test).<br/>"
            "• <b>Açık bulgular:</b> F-DISTILL, F-POISON, F-IMP, F-MCP — SECURITY.md.<br/>"
            "• <b>Bu sayıların göstermediği:</b> testlerin geçmesi <i>uygulamanın kendi "
            "varsayımlarına uyduğunu</i> gösterir; üretim güvenliğini göstermez. Bağımsız bir "
            "güvenlik denetimi yapılmamıştır.<br/>"
            "• <b>Açık kaynak deposu:</b> https://github.com/aikadimsoy/kasa-mcp (AGPL-3.0)",
            body_style))

        doc.build(story)
        print(f"[+] Profesyonel PDF Raporu başarıyla oluşturuldu: {pdf_filename}")


if __name__ == "__main__":
    output_pdf = "KASA_GUVENLIK_VE_MIMARI_RAPORU.pdf"
    build_pdf_report(output_pdf)
