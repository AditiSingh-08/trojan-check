import { jsPDF } from 'jspdf';

// Writes the analysis result to a PDF with wrapped text and automatic page breaks.
export function downloadPDFReport(result) {
  const doc = new jsPDF();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const maxWidth = doc.internal.pageSize.getWidth() - margin * 2;
  let y = 20;

  const write = (text, size = 11, bold = false, gap = 0) => {
    doc.setFontSize(size);
    doc.setFont('helvetica', bold ? 'bold' : 'normal');
    doc.splitTextToSize(String(text), maxWidth).forEach((line) => {
      if (y > pageHeight - 15) {
        doc.addPage();
        y = 20;
      }
      doc.text(line, margin, y);
      y += size * 0.45 + 0.8;
    });
    y += gap;
  };

  const { risk, hashes, virustotal, details } = result;

  write('Trojan Check - Static Analysis Report', 16, true, 4);
  write(`File: ${result.filename}`);
  write(`Type: ${result.file_type.toUpperCase()}   Size: ${result.size_bytes} bytes`);
  write(`SHA-256: ${hashes.sha256}`);
  write(`MD5: ${hashes.md5}`, 11, false, 4);

  write(`Risk: ${risk.band} (${risk.score}/100)`, 14, true, 3);
  risk.findings.forEach((f) => {
    const points = f.points ? ` (+${f.points})` : '';
    write(`[${f.severity.toUpperCase()}] ${f.title}${points}`, 11, true);
    if (f.detail) write(f.detail, 10, false, 2);
  });

  y += 2;
  write('VirusTotal', 12, true);
  if (!virustotal) {
    write('Lookup not configured on this server.', 10, false, 2);
  } else if (virustotal.status === 'found') {
    const total = virustotal.malicious + virustotal.suspicious + virustotal.harmless + virustotal.undetected;
    write(`${virustotal.malicious} of ${total} engines flagged this file as malicious.`, 10, false, 2);
  } else if (virustotal.status === 'not_found') {
    write('Hash not known to VirusTotal.', 10, false, 2);
  } else {
    write(virustotal.reason || 'Lookup unavailable.', 10, false, 2);
  }

  if (details.pe && !details.pe.error) {
    write('PE sections (name, entropy)', 12, true);
    details.pe.sections.forEach((s) => write(`${s.name || '(blank)'}  entropy ${s.entropy}`, 10));
    y += 2;
  }

  write(result.disclaimer, 9, false);
  doc.save(`${result.filename.replace(/\.[^.]+$/, '')}-report.pdf`);
}
