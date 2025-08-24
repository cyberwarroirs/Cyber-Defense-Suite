from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def generate_log_report(alerts, output_path):
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = [Paragraph("Log Anomaly Detection Report", styles['Heading1'])]

    data = [["Time", "Service", "Type", "Severity", "Description"]]
    for a in alerts:
        data.append([str(a.get("timestamp", "")), a["service"], a["type"], a["severity"], a["description"]])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black)
    ]))
    elements.append(table)
    doc.build(elements)
