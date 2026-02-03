import type { ScanResult, RiskScore } from '../../api/types'

const LEVEL_COLORS: Record<string, [number, number, number]> = {
  Critical: [239, 68, 68],
  High:     [249, 115, 22],
  Medium:   [234, 179, 8],
  Low:      [34, 197, 94],
  Info:     [99, 102, 241],
}

const LEVEL_BG: Record<string, [number, number, number]> = {
  Critical: [254, 242, 242],
  High:     [255, 247, 237],
  Medium:   [254, 252, 232],
  Low:      [240, 253, 244],
  Info:     [238, 242, 255],
}

export async function generateReport(result: ScanResult): Promise<void> {
  const { default: jsPDF } = await import('jspdf')

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
  const pw = doc.internal.pageSize.getWidth()
  const ph = doc.internal.pageSize.getHeight()
  const m = 18
  const cw = pw - m * 2
  let y = 0
  let pageNum = 1

  const checkPage = (needed: number) => {
    if (y + needed > ph - 25) {
      addFooter()
      doc.addPage()
      pageNum++
      y = m
    }
  }

  const addFooter = () => {
    doc.setFillColor(245, 245, 250)
    doc.rect(0, ph - 14, pw, 14, 'F')
    doc.setFontSize(7)
    doc.setTextColor(140, 140, 155)
    doc.text('GlitchForge  |  ML-Powered Vulnerability Assessment  |  Confidential', m, ph - 6)
    doc.text(`Page ${pageNum}`, pw - m, ph - 6, { align: 'right' })
  }

  // ========================================
  //  COVER PAGE
  // ========================================
  // Dark header block
  doc.setFillColor(10, 11, 16)
  doc.rect(0, 0, pw, 80, 'F')

  // Accent gradient bar
  doc.setFillColor(129, 140, 248)
  doc.rect(0, 80, pw, 1.5, 'F')
  doc.setFillColor(167, 139, 250)
  doc.rect(0, 81.5, pw, 0.5, 'F')

  // Logo text
  doc.setTextColor(232, 234, 240)
  doc.setFontSize(36)
  doc.setFont('helvetica', 'bold')
  doc.text('GlitchForge', m, 32)

  // Subtitle
  doc.setFontSize(12)
  doc.setTextColor(129, 140, 248)
  doc.setFont('helvetica', 'normal')
  doc.text('Vulnerability Assessment Report', m, 44)

  // Metadata lines
  doc.setFontSize(9)
  doc.setTextColor(140, 150, 180)
  doc.text(`Target:      ${result.url}`, m, 56)
  doc.text(`Date:        ${new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })}`, m, 63)
  doc.text(`Scan Time:   ${(result.total_time ?? result.scan_time).toFixed(2)}s`, m, 70)

  y = 96

  // ========================================
  //  EXECUTIVE SUMMARY
  // ========================================
  doc.setFontSize(16)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(40, 40, 50)
  doc.text('Executive Summary', m, y)
  doc.setDrawColor(129, 140, 248)
  doc.setLineWidth(0.6)
  doc.line(m, y + 2.5, m + 48, y + 2.5)
  y += 14

  // Summary metrics boxes
  const boxW = (cw - 9) / 4
  const metrics = [
    { label: 'Vulnerabilities', value: String(result.vulnerabilities_found), color: result.vulnerabilities_found > 0 ? LEVEL_COLORS.Critical : LEVEL_COLORS.Low },
    { label: 'Avg Risk Score', value: result.statistics ? result.statistics.average_risk_score.toFixed(1) : 'N/A', color: [129, 140, 248] as [number, number, number] },
    { label: 'ML Agreement', value: result.statistics ? `${result.statistics.model_agreement_rate?.toFixed(0) ?? '—'}%` : 'N/A', color: [129, 140, 248] as [number, number, number] },
    { label: 'Scan Duration', value: `${(result.total_time ?? result.scan_time).toFixed(2)}s`, color: [129, 140, 248] as [number, number, number] },
  ]

  metrics.forEach((metric, i) => {
    const x = m + i * (boxW + 3)

    // Card background
    doc.setFillColor(248, 248, 252)
    doc.roundedRect(x, y, boxW, 24, 2, 2, 'F')

    // Top accent stripe
    doc.setFillColor(metric.color[0], metric.color[1], metric.color[2])
    doc.roundedRect(x, y, boxW, 2.5, 2, 2, 'F')

    // Value
    doc.setFontSize(18)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(metric.color[0], metric.color[1], metric.color[2])
    doc.text(metric.value, x + boxW / 2, y + 14, { align: 'center' })

    // Label
    doc.setFontSize(6.5)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(110, 110, 125)
    doc.text(metric.label.toUpperCase(), x + boxW / 2, y + 20, { align: 'center' })
  })
  y += 32

  // ========================================
  //  SEVERITY BREAKDOWN
  // ========================================
  if (result.statistics?.risk_levels) {
    doc.setFontSize(13)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(40, 40, 50)
    doc.text('Severity Distribution', m, y)
    y += 9

    const levels = ['Critical', 'High', 'Medium', 'Low', 'Info']
    const total = result.vulnerabilities_found || 1

    // Stacked bar
    let barX = m
    const barH = 7
    levels.forEach(level => {
      const count = result.statistics!.risk_levels[level] || 0
      if (count === 0) return
      const w = (count / total) * cw
      const rgb = LEVEL_COLORS[level]
      doc.setFillColor(rgb[0], rgb[1], rgb[2])
      doc.roundedRect(barX, y, Math.max(w, 4), barH, 1, 1, 'F')
      barX += w + 1
    })
    y += barH + 7

    // Legend
    let legendX = m
    levels.forEach(level => {
      const count = result.statistics!.risk_levels[level] || 0
      if (count === 0) return
      const rgb = LEVEL_COLORS[level]
      doc.setFillColor(rgb[0], rgb[1], rgb[2])
      doc.circle(legendX + 2, y - 1, 1.8, 'F')
      doc.setFontSize(8)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(70, 70, 85)
      doc.text(`${level}: ${count}`, legendX + 6, y)
      legendX += 36
    })
    y += 12
  }

  // ========================================
  //  VULNERABILITY DETAILS
  // ========================================
  doc.setFontSize(16)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(40, 40, 50)
  doc.text('Vulnerability Details', m, y)
  doc.setDrawColor(129, 140, 248)
  doc.setLineWidth(0.6)
  doc.line(m, y + 2.5, m + 52, y + 2.5)
  y += 14

  // Sort by risk score descending
  const sorted = [...result.risk_scores].sort((a, b) => b.risk_score - a.risk_score)

  sorted.forEach((vuln, idx) => {
    checkPage(60)
    renderVulnCard(doc, vuln, idx, m, cw, y)
    y = (doc as any).__lastY || y + 45
    y += 6
  })

  // ========================================
  //  DISCLAIMER / FINAL PAGE
  // ========================================
  checkPage(40)
  y += 6
  doc.setDrawColor(200, 200, 215)
  doc.setLineWidth(0.3)
  doc.line(m, y, m + cw, y)
  y += 8

  doc.setFontSize(10)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(80, 80, 95)
  doc.text('Disclaimer', m, y)
  y += 6

  doc.setFontSize(7.5)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(110, 110, 125)
  const disclaimer = 'This report was generated by GlitchForge, an ML-powered vulnerability scanner. Results are based on automated analysis using Random Forest, Neural Network models with SHAP and LIME explanations. Findings should be validated by a qualified security professional before remediation. This report is confidential and intended for authorised recipients only.'
  const disclaimerLines = doc.splitTextToSize(disclaimer, cw)
  doc.text(disclaimerLines, m, y)
  y += disclaimerLines.length * 3.5 + 8

  doc.setFontSize(8)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(129, 140, 248)
  doc.text('GlitchForge — ML-Powered Vulnerability Assessment', pw / 2, y, { align: 'center' })
  y += 5
  doc.setFontSize(7)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(140, 140, 155)
  doc.text('Bilal Almshmesh (U2687294)  |  University of East London', pw / 2, y, { align: 'center' })

  // Final footer
  addFooter()

  doc.save(`GlitchForge_Report_${new Date().toISOString().slice(0, 10)}.pdf`)
}

function renderVulnCard(
  doc: any,
  vuln: RiskScore,
  _index: number,
  m: number,
  cw: number,
  startY: number,
) {
  let y = startY
  const rgb = LEVEL_COLORS[vuln.risk_level] || [128, 128, 128]
  const bgRgb = LEVEL_BG[vuln.risk_level] || [248, 248, 252]

  // Card background
  const cardH = estimateCardHeight(doc, vuln, cw)
  doc.setFillColor(bgRgb[0], bgRgb[1], bgRgb[2])
  doc.roundedRect(m, y - 2, cw, cardH, 2.5, 2.5, 'F')

  // Left severity accent bar
  doc.setFillColor(rgb[0], rgb[1], rgb[2])
  doc.roundedRect(m, y - 2, 3, cardH, 1.5, 1.5, 'F')

  // Header row: [SEVERITY PILL] Type ........... Score/100
  // Severity pill
  const pillText = vuln.risk_level.toUpperCase()
  const pillW = doc.getTextWidth(pillText) * 1.1 + 7
  doc.setFillColor(rgb[0], rgb[1], rgb[2])
  doc.roundedRect(m + 7, y, pillW, 5.5, 1.5, 1.5, 'F')
  doc.setTextColor(255, 255, 255)
  doc.setFontSize(7)
  doc.setFont('helvetica', 'bold')
  doc.text(pillText, m + 7 + pillW / 2, y + 4, { align: 'center' })

  // Vulnerability type as the title (instead of scan ID)
  doc.setFontSize(10)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(40, 40, 50)
  const vulnTitle = vuln.what?.vulnerability_type || 'Unknown'
  doc.text(vulnTitle, m + 7 + pillW + 4, y + 4.2)

  // Score on right
  doc.setFontSize(14)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(rgb[0], rgb[1], rgb[2])
  doc.text(`${vuln.risk_score}`, m + cw - 16, y + 4.2, { align: 'right' })
  doc.setFontSize(8)
  doc.setTextColor(140, 140, 155)
  doc.text('/100', m + cw - 6, y + 4.2, { align: 'right' })
  y += 10

  // CWE ID
  if (vuln.what?.cwe_id) {
    doc.setFontSize(7.5)
    doc.setFont('courier', 'normal')
    doc.setTextColor(129, 140, 248)
    doc.text(vuln.what.cwe_id, m + 8, y)
    y += 5
  }

  // Location details
  if (vuln.where) {
    doc.setFontSize(8)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(80, 80, 95)
    doc.text('URL', m + 8, y)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(60, 60, 70)
    const urlLines = doc.splitTextToSize(vuln.where.url, cw - 28)
    doc.text(urlLines, m + 22, y)
    y += urlLines.length * 4 + 2

    doc.setFont('helvetica', 'bold')
    doc.setTextColor(80, 80, 95)
    doc.text('Parameter', m + 8, y)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(60, 60, 70)
    doc.text(vuln.where.parameter || 'N/A', m + 32, y)
    y += 5

    if (vuln.where.method) {
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(80, 80, 95)
      doc.text('Method', m + 8, y)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(60, 60, 70)
      doc.text(vuln.where.method, m + 26, y)
      y += 5
    }
  }

  // Risk details row
  y += 1
  doc.setFillColor(240, 240, 248)
  doc.roundedRect(m + 6, y, cw - 12, 10, 1.5, 1.5, 'F')

  const riskItems = [
    { label: 'CVSS', value: vuln.cvss_base?.toFixed(1) || '—' },
    { label: 'Exploitability', value: vuln.cvss_exploitability?.toFixed(1) || '—' },
    { label: 'Impact', value: vuln.cvss_impact?.toFixed(1) || '—' },
    { label: 'Confidence', value: `${(vuln.confidence * 100).toFixed(0)}%` },
  ]

  const rItemW = (cw - 12) / riskItems.length
  riskItems.forEach((item, i) => {
    const rx = m + 6 + i * rItemW
    doc.setFontSize(6)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(110, 110, 125)
    doc.text(item.label.toUpperCase(), rx + rItemW / 2, y + 3.5, { align: 'center' })
    doc.setFontSize(8)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(50, 50, 60)
    doc.text(item.value, rx + rItemW / 2, y + 8, { align: 'center' })
  })
  y += 14

  // Separator
  doc.setDrawColor(210, 210, 225)
  doc.setLineWidth(0.15)
  doc.line(m + 8, y, m + cw - 8, y)
  y += 4

  // Remediation
  if (vuln.how_to_fix) {
    doc.setFontSize(8)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(34, 139, 80)
    doc.text('REMEDIATION', m + 8, y)
    y += 5
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(55, 55, 65)
    doc.setFontSize(7.5)
    const fixLines = doc.splitTextToSize(vuln.how_to_fix.remediation, cw - 18)
    const maxLines = Math.min(fixLines.length, 10)
    doc.text(fixLines.slice(0, maxLines), m + 8, y)
    y += maxLines * 3.3 + 2
    if (fixLines.length > maxLines) {
      doc.setTextColor(140, 140, 155)
      doc.setFontSize(6.5)
      doc.text('(continued...)', m + 8, y)
      y += 3
    }
  }

  y += 3
  ;(doc as any).__lastY = y
}

function estimateCardHeight(doc: any, vuln: RiskScore, cw: number): number {
  let h = 14 // header + pill
  if (vuln.what?.cwe_id) h += 5
  if (vuln.where) {
    const urlLines = doc.splitTextToSize(vuln.where.url, cw - 28)
    h += urlLines.length * 4 + 7
    if (vuln.where.method) h += 5
  }
  h += 16 // risk details row + separator
  if (vuln.how_to_fix) {
    const fixLines = doc.splitTextToSize(vuln.how_to_fix.remediation, cw - 18)
    h += Math.min(fixLines.length, 10) * 3.3 + 10
  }
  return h + 5
}
