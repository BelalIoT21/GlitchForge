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

const VERIFIED_COLORS: Record<string, [number, number, number]> = {
  confirmed:    [34, 197, 94],
  likely:       [234, 179, 8],
  unverified:   [156, 163, 175],
  false_positive: [239, 68, 68],
}

const VERIFIED_LABELS: Record<string, string> = {
  confirmed:    'VERIFIED',
  likely:       'LIKELY',
  unverified:   'UNVERIFIED',
  false_positive: 'FALSE POS.',
}

const TECHNIQUE_LABELS: Record<string, string> = {
  union_based_extraction: 'UNION-Based Extraction',
  boolean_blind:          'Boolean Blind Injection',
  time_based_blind:       'Time-Based Blind Injection',
  error_based:            'Error-Based Injection',
  canary_reflection:      'Canary Reflection',
  context_escape:         'Context-Aware Escape',
  csp_bypass:             'CSP Bypass',
  no_origin_submit:       'No-Origin Form Submit',
  token_omission:         'CSRF Token Omission',
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

  // Pentest stats
  const confirmedCount = result.risk_scores.filter(v => v.verified === 'confirmed').length
  const likelyCount = result.risk_scores.filter(v => v.verified === 'likely').length
  const testedCount = result.risk_scores.filter(v => v.pentest).length

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
    doc.text('GlitchForge  |  ML-Powered Vulnerability Scanner & Pentester  |  Confidential', m, ph - 6)
    doc.text(`Page ${pageNum}`, pw - m, ph - 6, { align: 'right' })
  }

  // ========================================
  //  COVER PAGE
  // ========================================
  doc.setFillColor(10, 11, 16)
  doc.rect(0, 0, pw, 90, 'F')

  // Accent gradient bar
  doc.setFillColor(129, 140, 248)
  doc.rect(0, 90, pw, 1.5, 'F')
  doc.setFillColor(167, 139, 250)
  doc.rect(0, 91.5, pw, 0.5, 'F')

  // Logo text
  doc.setTextColor(232, 234, 240)
  doc.setFontSize(36)
  doc.setFont('helvetica', 'bold')
  doc.text('GlitchForge', m, 30)

  // Subtitle
  doc.setFontSize(12)
  doc.setTextColor(129, 140, 248)
  doc.setFont('helvetica', 'normal')
  doc.text('Vulnerability Assessment & Pentest Validation Report', m, 42)

  // Metadata lines
  doc.setFontSize(9)
  doc.setTextColor(140, 150, 180)
  doc.text(`Target:         ${result.url}`, m, 56)
  doc.text(`Date:           ${new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })}`, m, 63)
  doc.text(`Total Time:     ${(result.total_time ?? result.scan_time).toFixed(2)}s`, m, 70)
  if (result.pentest_time) {
    doc.text(`Pentest Time:   ${result.pentest_time.toFixed(2)}s`, m, 77)
  }
  doc.text(`Findings:       ${result.vulnerabilities_found} confirmed vulnerabilities`, m, result.pentest_time ? 84 : 77)

  y = 106

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

  // Row 1: Core metrics (4 boxes)
  const boxW = (cw - 9) / 4
  const row1 = [
    { label: 'Vulnerabilities', value: String(result.vulnerabilities_found), color: result.vulnerabilities_found > 0 ? LEVEL_COLORS.Critical : LEVEL_COLORS.Low },
    { label: 'Avg Risk Score', value: result.statistics ? result.statistics.average_risk_score.toFixed(1) : 'N/A', color: [129, 140, 248] as [number, number, number] },
    { label: 'ML Agreement', value: result.statistics ? `${result.statistics.model_agreement_rate?.toFixed(0) ?? '—'}%` : 'N/A', color: [129, 140, 248] as [number, number, number] },
    { label: 'Total Duration', value: `${(result.total_time ?? result.scan_time).toFixed(1)}s`, color: [129, 140, 248] as [number, number, number] },
  ]

  renderMetricRow(doc, row1, m, y, boxW)
  y += 30

  // Row 2: Pentest metrics (4 boxes)
  const row2 = [
    { label: 'Pentest Verified', value: String(confirmedCount), color: [34, 197, 94] as [number, number, number] },
    { label: 'Likely Exploitable', value: String(likelyCount), color: [234, 179, 8] as [number, number, number] },
    { label: 'False Positives', value: String(result.filtered_count ?? 0), color: [239, 68, 68] as [number, number, number] },
    { label: 'Pentest Time', value: result.pentest_time ? `${result.pentest_time.toFixed(1)}s` : 'N/A', color: [167, 139, 250] as [number, number, number] },
  ]

  renderMetricRow(doc, row2, m, y, boxW)
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
  //  PENTEST VALIDATION SUMMARY
  // ========================================
  if (testedCount > 0) {
    checkPage(30)

    doc.setFontSize(13)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(40, 40, 50)
    doc.text('Pentest Validation Summary', m, y)
    y += 8

    // Summary text
    doc.setFontSize(8)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(70, 70, 85)
    const summaryText = `GlitchForge tested ${result.scanned_count ?? testedCount} potential vulnerabilities through controlled exploitation. ${confirmedCount} were confirmed exploitable, ${likelyCount} are likely exploitable, and ${result.filtered_count ?? 0} false positives were eliminated. Only verified findings are included below.`
    const summaryLines = doc.splitTextToSize(summaryText, cw)
    doc.text(summaryLines, m, y)
    y += summaryLines.length * 3.5 + 4

    // Techniques used table
    const techniques = new Map<string, number>()
    result.risk_scores.forEach(v => {
      if (v.pentest?.evidence?.technique) {
        const t = v.pentest.evidence.technique
        techniques.set(t, (techniques.get(t) || 0) + 1)
      }
    })

    if (techniques.size > 0) {
      doc.setFontSize(7.5)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(80, 80, 95)
      doc.text('Exploitation Techniques Used:', m, y)
      y += 5

      techniques.forEach((count, technique) => {
        doc.setFontSize(7)
        doc.setFont('helvetica', 'normal')
        doc.setTextColor(129, 140, 248)
        doc.text('\u2022', m + 4, y)
        doc.setTextColor(60, 60, 70)
        doc.text(`${TECHNIQUE_LABELS[technique] || technique} (${count}x)`, m + 8, y)
        y += 4
      })
      y += 4
    }
  }

  // ========================================
  //  VULNERABILITY DETAILS
  // ========================================
  // Sort by risk score descending
  const sorted = [...result.risk_scores].sort((a, b) => b.risk_score - a.risk_score)

  // Start findings on a fresh page so the header is never orphaned
  addFooter()
  doc.addPage()
  pageNum++
  y = m

  doc.setFontSize(16)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(40, 40, 50)
  doc.text('Vulnerability Details', m, y)
  doc.setDrawColor(129, 140, 248)
  doc.setLineWidth(0.6)
  doc.line(m, y + 2.5, m + 52, y + 2.5)
  y += 4

  doc.setFontSize(8)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(110, 110, 125)
  doc.text(`${sorted.length} vulnerabilities sorted by risk score (highest first)`, m, y + 4)
  y += 14

  const maxPageH = ph - 25 - m
  sorted.forEach((vuln, idx) => {
    const cardH = estimateCardHeight(doc, vuln, cw)
    // Only page-break for cards that fit on a single page
    // Large cards span pages via innerCheckPage inside renderVulnCard
    if (cardH + 8 <= maxPageH) {
      checkPage(cardH + 8)
    } else {
      checkPage(50)
    }
    renderVulnCard(doc, vuln, idx, m, cw, y, pw, ph, () => {
      addFooter()
      doc.addPage()
      pageNum++
      y = m
    })
    y = (doc as any).__lastY || y + 45
    y += 8
  })

  // ========================================
  //  DISCLAIMER / FINAL PAGE
  // ========================================
  checkPage(50)
  y += 6
  doc.setDrawColor(200, 200, 215)
  doc.setLineWidth(0.3)
  doc.line(m, y, m + cw, y)
  y += 10

  doc.setFontSize(10)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(80, 80, 95)
  doc.text('Disclaimer', m, y)
  y += 7

  doc.setFontSize(7.5)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(110, 110, 125)
  const disclaimer = 'This report was generated by GlitchForge, an ML-powered vulnerability scanner and pentester. Results are based on automated exploit validation and analysis using Random Forest, Neural Network models with SHAP and LIME explanations. Only confirmed and likely-exploitable findings are included. This report is confidential and intended for authorised recipients only.'
  const disclaimerLines = doc.splitTextToSize(disclaimer, cw)
  doc.text(disclaimerLines, m, y)
  y += disclaimerLines.length * 3.5 + 10

  doc.setFontSize(8)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(129, 140, 248)
  doc.text('GlitchForge — ML-Powered Vulnerability Scanner & Pentester', pw / 2, y, { align: 'center' })
  y += 5
  doc.setFontSize(7)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(140, 140, 155)
  doc.text('Bilal Almshmesh (U2687294)  |  University of East London', pw / 2, y, { align: 'center' })

  addFooter()

  doc.save(`GlitchForge_Report_${new Date().toISOString().slice(0, 10)}.pdf`)
}

// ========================================
//  METRIC ROW RENDERER
// ========================================
function renderMetricRow(
  doc: any,
  metrics: { label: string; value: string; color: [number, number, number] }[],
  m: number,
  y: number,
  boxW: number,
) {
  metrics.forEach((metric, i) => {
    const x = m + i * (boxW + 3)

    doc.setFillColor(248, 248, 252)
    doc.roundedRect(x, y, boxW, 24, 2, 2, 'F')

    doc.setFillColor(metric.color[0], metric.color[1], metric.color[2])
    doc.roundedRect(x, y, boxW, 2.5, 2, 2, 'F')

    doc.setFontSize(18)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(metric.color[0], metric.color[1], metric.color[2])
    doc.text(metric.value, x + boxW / 2, y + 14, { align: 'center' })

    doc.setFontSize(6.5)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(110, 110, 125)
    doc.text(metric.label.toUpperCase(), x + boxW / 2, y + 20, { align: 'center' })
  })
}

// ========================================
//  VULNERABILITY CARD RENDERER
// ========================================
function renderVulnCard(
  doc: any,
  vuln: RiskScore,
  _index: number,
  m: number,
  cw: number,
  startY: number,
  pw: number,
  ph: number,
  newPage: () => void,
) {
  let y = startY
  const rgb = LEVEL_COLORS[vuln.risk_level] || [128, 128, 128]
  const bgRgb = LEVEL_BG[vuln.risk_level] || [248, 248, 252]

  const innerCheckPage = (needed: number) => {
    if (y + needed > ph - 25) {
      newPage()
      y = m
    }
  }

  // Card background
  const cardH = estimateCardHeight(doc, vuln, cw)
  doc.setFillColor(bgRgb[0], bgRgb[1], bgRgb[2])
  doc.roundedRect(m, y - 2, cw, cardH, 2.5, 2.5, 'F')

  // Left severity accent bar
  doc.setFillColor(rgb[0], rgb[1], rgb[2])
  doc.roundedRect(m, y - 2, 3, cardH, 1.5, 1.5, 'F')

  // ── Header row: [SEVERITY] [VERIFIED] Type ........... Score/100 ──
  // Severity pill
  const pillText = vuln.risk_level.toUpperCase()
  const pillW = doc.getTextWidth(pillText) * 1.1 + 7
  doc.setFillColor(rgb[0], rgb[1], rgb[2])
  doc.roundedRect(m + 7, y, pillW, 5.5, 1.5, 1.5, 'F')
  doc.setTextColor(255, 255, 255)
  doc.setFontSize(7)
  doc.setFont('helvetica', 'bold')
  doc.text(pillText, m + 7 + pillW / 2, y + 4, { align: 'center' })

  // Verification status pill
  let afterPills = m + 7 + pillW + 3
  if (vuln.verified) {
    const vColor = VERIFIED_COLORS[vuln.verified] || [156, 163, 175]
    const vLabel = VERIFIED_LABELS[vuln.verified] || vuln.verified.toUpperCase()
    doc.setFontSize(6)
    const vW = doc.getTextWidth(vLabel) * 1.1 + 6
    doc.setFillColor(vColor[0], vColor[1], vColor[2])
    doc.roundedRect(afterPills, y + 0.5, vW, 4.5, 1.2, 1.2, 'F')
    doc.setTextColor(255, 255, 255)
    doc.setFont('helvetica', 'bold')
    doc.text(vLabel, afterPills + vW / 2, y + 3.8, { align: 'center' })
    afterPills += vW + 3
  }

  // Vulnerability type title
  doc.setFontSize(10)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(40, 40, 50)
  const vulnTitle = vuln.what?.vulnerability_type || 'Unknown'
  doc.text(vulnTitle, afterPills, y + 4.2)

  // Score on right
  doc.setFontSize(14)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(rgb[0], rgb[1], rgb[2])
  doc.text(`${vuln.risk_score}`, m + cw - 16, y + 4.2, { align: 'right' })
  doc.setFontSize(8)
  doc.setTextColor(140, 140, 155)
  doc.text('/100', m + cw - 6, y + 4.2, { align: 'right' })
  y += 10

  // ── CWE ID ──
  if (vuln.what?.cwe_id) {
    doc.setFontSize(7.5)
    doc.setFont('courier', 'normal')
    doc.setTextColor(129, 140, 248)
    doc.text(vuln.what.cwe_id, m + 8, y)
    y += 5
  }

  // ── Location details ──
  if (vuln.where) {
    doc.setFontSize(7)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(100, 100, 115)
    doc.text('LOCATION', m + 8, y)
    y += 4

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

  // ── Risk metrics row ──
  y += 2
  doc.setFillColor(240, 240, 248)
  doc.roundedRect(m + 6, y, cw - 12, 10, 1.5, 1.5, 'F')

  const riskItems = [
    { label: 'CVSS', value: vuln.cvss_base?.toFixed(1) || '—' },
    { label: 'Exploitability', value: vuln.cvss_exploitability?.toFixed(1) || '—' },
    { label: 'Impact', value: vuln.cvss_impact?.toFixed(1) || '—' },
    { label: 'Confidence', value: `${(vuln.confidence * 100).toFixed(0)}%` },
    { label: 'Verified', value: vuln.verified ? VERIFIED_LABELS[vuln.verified] || vuln.verified : 'N/A' },
  ]

  const rItemW = (cw - 12) / riskItems.length
  riskItems.forEach((item, i) => {
    const rx = m + 6 + i * rItemW
    doc.setFontSize(5.5)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(110, 110, 125)
    doc.text(item.label.toUpperCase(), rx + rItemW / 2, y + 3.5, { align: 'center' })
    doc.setFontSize(7.5)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(50, 50, 60)
    doc.text(item.value, rx + rItemW / 2, y + 8, { align: 'center' })
  })
  y += 14

  // ── Pentest Evidence ──
  if (vuln.pentest?.evidence) {
    const ev = vuln.pentest.evidence

    // Section label
    doc.setDrawColor(129, 140, 248)
    doc.setLineWidth(0.3)
    doc.line(m + 8, y, m + cw - 8, y)
    y += 5

    doc.setFontSize(7)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(129, 140, 248)
    doc.text('PENTEST EVIDENCE', m + 8, y)

    // Technique + duration on the right
    doc.setFontSize(6.5)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(100, 100, 115)
    const techLabel = TECHNIQUE_LABELS[ev.technique] || ev.technique
    const durLabel = vuln.pentest.duration_seconds ? ` | ${vuln.pentest.duration_seconds.toFixed(1)}s` : ''
    doc.text(`${techLabel}${durLabel}`, m + cw - 8, y, { align: 'right' })
    y += 6

    // Extracted data
    if (ev.extracted_data && ev.extracted_data.length > 0) {
      innerCheckPage(16)
      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(239, 68, 68)
      doc.text('Extracted Data:', m + 8, y)
      y += 4

      ev.extracted_data.forEach((data: string) => {
        innerCheckPage(6)
        // Red-bordered code box
        doc.setFillColor(254, 242, 242)
        doc.setDrawColor(239, 68, 68)
        doc.setLineWidth(0.2)
        const dataLines = doc.splitTextToSize(data, cw - 24)
        const boxH = dataLines.length * 3.3 + 3
        doc.roundedRect(m + 8, y - 1, cw - 16, boxH, 1, 1, 'FD')
        doc.setFontSize(7)
        doc.setFont('courier', 'normal')
        doc.setTextColor(180, 30, 30)
        doc.text(dataLines, m + 10, y + 2)
        y += boxH + 2
      })
      y += 1
    }

    // Proof of Concept command
    if (ev.poc_command) {
      innerCheckPage(16)
      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(80, 80, 95)
      doc.text('Proof of Concept:', m + 8, y)
      y += 4

      // Dark code block
      const pocLines = doc.splitTextToSize(ev.poc_command, cw - 24)
      const maxPocLines = Math.min(pocLines.length, 6)
      const pocH = maxPocLines * 3.3 + 4
      doc.setFillColor(30, 31, 38)
      doc.roundedRect(m + 8, y - 1, cw - 16, pocH, 1.5, 1.5, 'F')
      doc.setFontSize(5.5)
      doc.setFont('courier', 'normal')
      doc.setTextColor(180, 190, 210)
      doc.text(pocLines.slice(0, maxPocLines), m + 10, y + 2.5)
      if (pocLines.length > maxPocLines) {
        doc.setTextColor(129, 140, 248)
        doc.text('...', m + 10, y + pocH - 2)
      }
      y += pocH + 2
    }

    // Reproduction steps
    if (ev.reproduction_steps && ev.reproduction_steps.length > 0) {
      innerCheckPage(14)
      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(80, 80, 95)
      doc.text('Reproduction Steps:', m + 8, y)
      y += 4.5

      ev.reproduction_steps.forEach((step: string, i: number) => {
        innerCheckPage(6)
        // Step number circle
        doc.setFillColor(129, 140, 248)
        doc.circle(m + 11, y, 2, 'F')
        doc.setFontSize(5.5)
        doc.setFont('helvetica', 'bold')
        doc.setTextColor(255, 255, 255)
        doc.text(String(i + 1), m + 11, y + 1, { align: 'center' })

        // Step text
        doc.setFontSize(7)
        doc.setFont('helvetica', 'normal')
        doc.setTextColor(60, 60, 70)
        const stepLines = doc.splitTextToSize(step, cw - 28)
        doc.text(stepLines, m + 16, y + 1)
        y += stepLines.length * 3.3 + 2
      })
      y += 1
    }

    // Impact description
    if (ev.impact_description) {
      innerCheckPage(10)
      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(249, 115, 22)
      doc.text('Impact:', m + 8, y)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(70, 70, 85)
      const impactLines = doc.splitTextToSize(ev.impact_description, cw - 28)
      doc.text(impactLines, m + 24, y)
      y += impactLines.length * 3.3 + 2
    }
  }

  // ── Separator before remediation ──
  doc.setDrawColor(210, 210, 225)
  doc.setLineWidth(0.15)
  doc.line(m + 8, y, m + cw - 8, y)
  y += 4

  // ── Remediation ──
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

// ========================================
//  CARD HEIGHT ESTIMATOR
// ========================================
function estimateCardHeight(doc: any, vuln: RiskScore, cw: number): number {
  let h = 14 // header + pill
  if (vuln.what?.cwe_id) h += 5
  if (vuln.where) {
    h += 4 // LOCATION label
    const urlLines = doc.splitTextToSize(vuln.where.url, cw - 28)
    h += urlLines.length * 4 + 7
    if (vuln.where.method) h += 5
  }
  h += 18 // risk metrics row + spacing

  // Pentest evidence
  if (vuln.pentest?.evidence) {
    const ev = vuln.pentest.evidence
    h += 12 // section header + separator

    if (ev.extracted_data?.length) {
      h += 6
      ev.extracted_data.forEach((data: string) => {
        const lines = doc.splitTextToSize(data, cw - 24)
        h += lines.length * 3.3 + 6
      })
    }

    if (ev.poc_command) {
      const pocLines = doc.splitTextToSize(ev.poc_command, cw - 24)
      h += Math.min(pocLines.length, 6) * 3.3 + 10
    }

    if (ev.reproduction_steps?.length) {
      h += 6
      ev.reproduction_steps.forEach((step: string) => {
        const lines = doc.splitTextToSize(step, cw - 28)
        h += lines.length * 3.3 + 2
      })
    }

    if (ev.impact_description) {
      const lines = doc.splitTextToSize(ev.impact_description, cw - 28)
      h += lines.length * 3.3 + 4
    }
  }

  h += 6 // separator
  if (vuln.how_to_fix) {
    const fixLines = doc.splitTextToSize(vuln.how_to_fix.remediation, cw - 18)
    h += Math.min(fixLines.length, 10) * 3.3 + 10
  }
  return h + 5
}
