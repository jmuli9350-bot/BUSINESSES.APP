export type DailySales = { records: number; total: number }
type SalesSummary = {
  business?: { date?: string; name?: string; ownerName?: string; currency?: string }
  salesThisMonth?: DailySales
  salesByDate?: Record<string, DailySales>
  salesByDateFrom?: string
}

const asRecord = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
const asAmount = (value: unknown) => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.round(value * 100) / 100 : 0
const asCount = (value: unknown) => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0
const asLabel = (value: unknown, fallback = '') => typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 100) || fallback : fallback

const isDateKey = (value: string) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false
  const parsed = new Date(`${value}T00:00:00.000Z`)
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value
}

const dateKey = (date: Date) => date.toISOString().slice(0, 10)
const utcDate = (key: string) => new Date(`${key}T00:00:00.000Z`)
const startOfWeek = (date: Date) => {
  const start = new Date(date)
  start.setUTCDate(start.getUTCDate() - (start.getUTCDay() + 6) % 7)
  return start
}

export const normalizeSalesByDate = (value: unknown): Record<string, DailySales> => Object.fromEntries(
  Object.entries(asRecord(value))
    .filter(([date, totals]) => isDateKey(date) && totals && typeof totals === 'object' && !Array.isArray(totals))
    .sort(([dateA], [dateB]) => dateB.localeCompare(dateA))
    .slice(0, 500)
    .map(([date, totals]) => {
      const dailySales = asRecord(totals)
      return [date, { records: asCount(dailySales.records), total: asAmount(dailySales.total) }]
    }),
)

const monthPattern = 'january|february|march|april|may|june|july|august|september|sept|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec'
const monthNumbers: Record<string, string> = {
  jan: '01', january: '01', feb: '02', february: '02', mar: '03', march: '03',
  apr: '04', april: '04', may: '05', jun: '06', june: '06', jul: '07', july: '07',
  aug: '08', august: '08', sep: '09', sept: '09', september: '09', oct: '10',
  october: '10', nov: '11', november: '11', dec: '12', december: '12',
}

const parseDateMentions = (query: string, today: string) => {
  const year = today.slice(0, 4)
  const monthFirst = new RegExp(`\\b(${monthPattern})\\s+(\\d{1,2})(?:st|nd|rd|th)?(?:,?\\s+(20\\d{2}))?\\b`, 'g')
  const dayFirst = new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(${monthPattern})(?:,?\\s+(20\\d{2}))?\\b`, 'g')
  const mentions: Array<{ index: number; end: number; date: string }> = []
  for (const match of query.matchAll(/\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})\b/g)) {
    mentions.push({ index: match.index, end: match.index + match[0].length, date: `${match[1]}-${match[2].padStart(2, '0')}-${match[3].padStart(2, '0')}` })
  }
  for (const match of query.matchAll(/\b(\d{1,2})[/-](\d{1,2})[/-](20\d{2})\b/g)) {
    mentions.push({ index: match.index, end: match.index + match[0].length, date: `${match[3]}-${match[2].padStart(2, '0')}-${match[1].padStart(2, '0')}` })
  }
  for (const match of query.matchAll(/\b(\d{1,2})[/-](\d{1,2})\b/g)) {
    mentions.push({ index: match.index, end: match.index + match[0].length, date: `${year}-${match[2].padStart(2, '0')}-${match[1].padStart(2, '0')}` })
  }
  for (const match of query.matchAll(monthFirst)) {
    mentions.push({ index: match.index, end: match.index + match[0].length, date: `${match[3] || year}-${monthNumbers[match[1]]}-${match[2].padStart(2, '0')}` })
  }
  for (const match of query.matchAll(dayFirst)) {
    mentions.push({ index: match.index, end: match.index + match[0].length, date: `${match[3] || year}-${monthNumbers[match[2]]}-${match[1].padStart(2, '0')}` })
  }
  const validMentions = mentions
    .filter((mention) => isDateKey(mention.date))
    .sort((first, second) => first.index - second.index || second.end - second.index - (first.end - first.index))
  const nonOverlappingMentions: typeof validMentions = []
  for (const mention of validMentions) {
    const previous = nonOverlappingMentions[nonOverlappingMentions.length - 1]
    if (!previous || mention.index >= previous.end) nonOverlappingMentions.push(mention)
  }
  return nonOverlappingMentions
}

const explicitDateRange = (query: string, today: string): { start: string; end: string } | null => {
  const separator = '(?:to|through|until|and|[-–])'
  const prefix = '(?:(?:from|between)\\s+)?'
  const year = today.slice(0, 4)
  const patterns = [
    new RegExp(`\\b${prefix}(${monthPattern})\\s+(\\d{1,2})(?:st|nd|rd|th)?(?:,?\\s+(20\\d{2}))?\\s*${separator}\\s*(?:(${monthPattern})\\s+)?(\\d{1,2})(?:st|nd|rd|th)?(?:,?\\s+(20\\d{2}))?\\b`),
    new RegExp(`\\b${prefix}(\\d{1,2})(?:st|nd|rd|th)?\\s+(${monthPattern})(?:,?\\s+(20\\d{2}))?\\s*${separator}\\s*(?:(\\d{1,2})(?:st|nd|rd|th)?\\s+)?(${monthPattern})?\\s*(\\d{1,2})?(?:st|nd|rd|th)?(?:,?\\s+(20\\d{2}))?\\b`),
    new RegExp(`\\b(?:from\\s+)?(\\d{1,2})(?:st|nd|rd|th)?\\s*${separator}\\s*(\\d{1,2})(?:st|nd|rd|th)?\\s+(${monthPattern})(?:,?\\s+(20\\d{2}))?\\b`),
  ]

  const monthFirst = query.match(patterns[0])
  if (monthFirst) {
    const first = `${monthFirst[3] || monthFirst[6] || year}-${monthNumbers[monthFirst[1]]}-${monthFirst[2].padStart(2, '0')}`
    const second = `${monthFirst[6] || monthFirst[3] || year}-${monthNumbers[monthFirst[4] || monthFirst[1]]}-${monthFirst[5].padStart(2, '0')}`
    if (isDateKey(first) && isDateKey(second)) return first <= second ? { start: first, end: second } : { start: second, end: first }
  }

  const dayFirst = query.match(patterns[1])
  if (dayFirst) {
    const first = `${dayFirst[3] || dayFirst[7] || year}-${monthNumbers[dayFirst[2]]}-${dayFirst[1].padStart(2, '0')}`
    const secondMonth = dayFirst[5] || dayFirst[2]
    const secondDay = dayFirst[6] || dayFirst[4] || dayFirst[1]
    const second = `${dayFirst[7] || dayFirst[3] || year}-${monthNumbers[secondMonth]}-${secondDay.padStart(2, '0')}`
    if (isDateKey(first) && isDateKey(second)) return first <= second ? { start: first, end: second } : { start: second, end: first }
  }

  const sameMonth = query.match(patterns[2])
  if (sameMonth) {
    const first = `${sameMonth[4] || year}-${monthNumbers[sameMonth[3]]}-${sameMonth[1].padStart(2, '0')}`
    const second = `${sameMonth[4] || year}-${monthNumbers[sameMonth[3]]}-${sameMonth[2].padStart(2, '0')}`
    if (isDateKey(first) && isDateKey(second)) return first <= second ? { start: first, end: second } : { start: second, end: first }
  }
  return null
}

const parseRequestedPeriod = (question: string, today: string): { start: string; end: string } => {
  const query = question.toLowerCase()
  const currentDate = utcDate(today)
  const startDate = new Date(currentDate)
  const endDate = new Date(currentDate)
  if (/\b(today|tonight)\b/.test(query)) return { start: today, end: today }
  if (/\byesterday\b/.test(query)) {
    startDate.setUTCDate(startDate.getUTCDate() - 1)
    const yesterday = dateKey(startDate)
    return { start: yesterday, end: yesterday }
  }
  if (/\b(last|past)\s+7\s+days\b|\bpast week\b/.test(query)) {
    startDate.setUTCDate(startDate.getUTCDate() - 6)
    return { start: dateKey(startDate), end: today }
  }
  if (/\b(last|past)\s+30\s+days\b/.test(query)) {
    startDate.setUTCDate(startDate.getUTCDate() - 29)
    return { start: dateKey(startDate), end: today }
  }
  if (/\bthis week\b/.test(query)) return { start: dateKey(startOfWeek(currentDate)), end: today }
  if (/\blast week\b/.test(query)) {
    const thisWeek = startOfWeek(currentDate)
    endDate.setTime(thisWeek.getTime() - 86400000)
    endDate.setUTCHours(0, 0, 0, 0)
    const lastWeekStart = new Date(endDate)
    lastWeekStart.setUTCDate(lastWeekStart.getUTCDate() - 6)
    return { start: dateKey(lastWeekStart), end: dateKey(endDate) }
  }
  if (/\bthis month\b|\bmonth to date\b|\bmonthly\b/.test(query)) {
    startDate.setUTCDate(1)
    return { start: dateKey(startDate), end: today }
  }
  if (/\blast month\b/.test(query)) {
    startDate.setUTCDate(1)
    startDate.setUTCMonth(startDate.getUTCMonth() - 1)
    endDate.setUTCDate(0)
    return { start: dateKey(startDate), end: dateKey(endDate) }
  }
  if (/\bthis year\b|\byear to date\b/.test(query)) {
    startDate.setUTCMonth(0, 1)
    return { start: dateKey(startDate), end: today }
  }
  if (/\blast year\b/.test(query)) {
    const year = currentDate.getUTCFullYear() - 1
    return { start: `${year}-01-01`, end: `${year}-12-31` }
  }

  const requestedRange = explicitDateRange(query, today)
  if (requestedRange) return requestedRange

  const mentions = parseDateMentions(query, today)
  if (mentions.length >= 2 && /\b(from|between|to|through|until|and)\b|[-–]/.test(query)) {
    const first = mentions[0].date
    let second = mentions[1].date
    const sameMonthDayRange = query.match(/\b(?:from|between)\s+(?:\p{L}+\s+)?\d{1,2}(?:st|nd|rd|th)?\s+(?:to|through|until|and|[-–])\s+(\d{1,2})(?:st|nd|rd|th)?\b/u)
    if (sameMonthDayRange) {
      const monthAndYear = first.slice(0, 8)
      second = `${monthAndYear}${sameMonthDayRange[1].padStart(2, '0')}`
    }
    return first <= second ? { start: first, end: second } : { start: second, end: first }
  }
  if (mentions.length) return { start: mentions[0].date, end: mentions[0].date }
  return { start: today, end: today }
}

const displayDate = (date: string) => new Intl.DateTimeFormat('en-GB', {
  day: 'numeric',
  month: 'long',
  year: 'numeric',
  timeZone: 'UTC',
}).format(new Date(`${date}T00:00:00.000Z`))

const displayPeriod = (start: string, end: string) => start === end
  ? displayDate(start)
  : `${displayDate(start)} – ${displayDate(end)}`

export const isSalesQuestion = (question: string) => /\b(sales|sale|revenue|sold|selling|income|transaction|transactions)\b/i.test(question)

export const createLocalAnswer = (question: string, summary: SalesSummary & Record<string, unknown>) => {
  const business = asRecord(summary.business)
  const businessName = asLabel(business.name, 'your business')
  const ownerName = asLabel(business.ownerName, 'there')
  const team = asRecord(summary.team)
  const attendance = asRecord(summary.attendanceToday)
  const attendanceCounts = asRecord(attendance.statusCounts)
  const payroll = asRecord(summary.payrollThisMonth)
  const sales = asRecord(summary.salesThisMonth)
  const salesByDate = normalizeSalesByDate(summary.salesByDate)
  const salesByDateFrom = asLabel(summary.salesByDateFrom)
  const deductions = asRecord(summary.deductionsThisMonth)
  const inventory = asRecord(summary.inventory)
  const currency = asLabel(business.currency, 'KES')
  const today = asLabel(business.date)
  const money = (value: unknown) => `${currency} ${asAmount(value).toLocaleString()}`
  const count = (value: unknown) => asCount(value).toLocaleString()
  const questionWithoutGreeting = question.trim().replace(/^(hi|hello|hey|good morning|good afternoon|good evening|good night)\b[\s,.!]*(?:there\b[\s,.!]*)?/i, '').trim()
  if (!questionWithoutGreeting) {
    return `Hello, ${ownerName}! How can I help you with ${businessName} today?`
  }
  const query = questionWithoutGreeting.toLowerCase()

  if (/\b(help|what can you do|what do you know|what can i ask)\b/.test(query)) {
    return `I can help with ${businessName}’s sales, payroll, deductions, attendance, team, and stock using the workspace totals.`
  }
  if (isSalesQuestion(query)) {
    const period = parseRequestedPeriod(query, today)
    if (salesByDateFrom && period.start < salesByDateFrom) {
      return `Sales history for **${displayPeriod(period.start, period.end)}** is not available in the workspace summary.`
    }
    if (period.start === period.end) {
      const dailySales = salesByDate[period.start]
      if (!dailySales || dailySales.records === 0) {
        return `No sales were recorded for **${displayDate(period.start)}**.`
      }
      return `${businessName} recorded **${money(dailySales.total)}** in sales across **${count(dailySales.records)} ${dailySales.records === 1 ? 'record' : 'records'}** on **${displayDate(period.start)}**.`
    }
    const periodTotals = Object.entries(salesByDate).reduce((totals, [date, dailySales]) => {
      if (date >= period.start && date <= period.end) {
        totals.records += dailySales.records
        totals.total += dailySales.total
      }
      return totals
    }, { records: 0, total: 0 })
    if (periodTotals.records === 0) return `No sales were recorded from **${displayPeriod(period.start, period.end)}**.`
    return `${businessName} recorded **${money(periodTotals.total)}** in sales across **${count(periodTotals.records)} ${periodTotals.records === 1 ? 'record' : 'records'}** from **${displayPeriod(period.start, period.end)}**.`
  }
  if (/\b(payroll|unpaid|outstanding|owed|wages|salary|salaries)\b/.test(query)) {
    return `${ownerName}, unpaid payroll this month is **${money(payroll.outstanding)}**.`
  }
  if (/\b(attendance|present|late|absent|off today|checked in)\b/.test(query)) {
    return `Today: **${count(attendanceCounts.Present)} present**, **${count(attendanceCounts.Late)} late**, **${count(attendanceCounts.Absent)} absent**, and **${count(attendanceCounts.Off)} off**. ${count(attendance.recordedWorkers)} attendance records are recorded.`
  }
  if (/\b(team|workers|employees|staff|headcount)\b/.test(query)) {
    return `There ${asCount(team.activeWorkers) === 1 ? 'is' : 'are'} **${count(team.activeWorkers)} active ${asCount(team.activeWorkers) === 1 ? 'worker' : 'workers'}** in your team.`
  }
  if (/\b(stock|inventory|low[\s-]?stock|reorder)\b/.test(query)) {
    return `You have **${count(inventory.lowStockItems)} low-stock ${asCount(inventory.lowStockItems) === 1 ? 'item' : 'items'}** out of ${count(inventory.trackedItems)} tracked.`
  }
  if (/\b(deduction|deductions|penalt(y|ies))\b/.test(query)) {
    return `This month there are **${count(deductions.records)} deductions** totaling **${money(deductions.total)}**.`
  }
  if (/\b(business|doing|performance|summary|attention|overview)\b/.test(query)) {
    return `${ownerName}, ${businessName}’s sales this month are **${money(sales.total)}**; unpaid payroll is **${money(payroll.outstanding)}**. Today, **${count(attendanceCounts.Present)} are present** and **${count(inventory.lowStockItems)} stock ${asCount(inventory.lowStockItems) === 1 ? 'item needs' : 'items need'} attention**.`
  }
  return `I can help with ${businessName}’s sales, payroll, deductions, attendance, team, and stock. What would you like to check?`
}
