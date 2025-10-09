"""
Mernithian Conversation PDF Generator
Creates a professional PDF from the conversation markdown
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY


def create_pdf():
    # Create PDF
    pdf_path = r"C:\Users\Corbin\development\mernithian_conversation.pdf"
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
    )

    # Container for elements
    elements = []

    # Styles
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=colors.HexColor("#1a1a1a"),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )

    heading1_style = ParagraphStyle(
        "CustomHeading1",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=colors.HexColor("#2c3e50"),
        spaceAfter=12,
        spaceBefore=12,
        fontName="Helvetica-Bold",
    )

    heading2_style = ParagraphStyle(
        "CustomHeading2",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#34495e"),
        spaceAfter=10,
        spaceBefore=10,
        fontName="Helvetica-Bold",
    )

    body_style = ParagraphStyle(
        "CustomBody", parent=styles["Normal"], fontSize=10, alignment=TA_JUSTIFY, spaceAfter=6
    )

    ParagraphStyle(
        "CustomCode",
        parent=styles["Code"],
        fontSize=9,
        fontName="Courier",
        leftIndent=20,
        textColor=colors.HexColor("#2c3e50"),
        backColor=colors.HexColor("#f8f9fa"),
    )

    # Title
    elements.append(Paragraph("MERNITHIAN LOGOGRAPHIC SYSTEM", title_style))
    elements.append(Paragraph("Comprehensive Archive & Mathematical Formalization", heading2_style))
    elements.append(Spacer(1, 0.3 * inch))

    # Metadata
    metadata_data = [
        ["Archive Date:", "September 29, 2025"],
        ["Document Type:", "Constructed Language System Development"],
        ["Classification:", "Linguistic Research & Theoretical Framework"],
    ]

    metadata_table = Table(metadata_data, colWidths=[2 * inch, 4 * inch])
    metadata_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8f4f8")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )

    elements.append(metadata_table)
    elements.append(Spacer(1, 0.4 * inch))

    # Read markdown and parse content
    with open(
        r"C:\Users\Corbin\development\mernithian_conversation.md", "r", encoding="utf-8"
    ) as f:
        content = f.read()

    # Split content into lines
    lines = content.split("\n")

    for line in lines[30:]:  # Skip title and metadata that we already added
        line = line.strip()

        if not line:
            elements.append(Spacer(1, 0.1 * inch))
            continue

        # Handle headers
        if line.startswith("## "):
            if len(elements) > 5:  # Add page break before major sections
                elements.append(PageBreak())
            elements.append(Paragraph(line[3:], heading1_style))

        elif line.startswith("### "):
            elements.append(Paragraph(line[4:], heading2_style))

        elif line.startswith("#### "):
            elements.append(Paragraph(line[5:], body_style))

        # Handle code blocks
        elif line.startswith("```"):
            continue

        # Handle horizontal rules
        elif line.startswith("---"):
            elements.append(Spacer(1, 0.2 * inch))

        # Handle bullets
        elif line.startswith("- ") or line.startswith("* "):
            bullet_text = "• " + line[2:]
            elements.append(Paragraph(bullet_text, body_style))

        # Handle numbered lists
        elif line and line[0].isdigit() and ". " in line:
            elements.append(Paragraph(line, body_style))

        # Handle bold text
        elif "**" in line:
            # Simple bold handling
            line = line.replace("**", "<b>", 1).replace("**", "</b>", 1)
            elements.append(Paragraph(line, body_style))

        # Regular text
        elif line and not line.startswith("#"):
            elements.append(Paragraph(line, body_style))

    # Build PDF
    doc.build(elements)
    print(f"PDF created successfully at: {pdf_path}")
    return pdf_path


if __name__ == "__main__":
    try:
        pdf_path = create_pdf()
    except Exception as e:
        print(f"Error creating PDF: {e}")
        import traceback

        traceback.print_exc()
