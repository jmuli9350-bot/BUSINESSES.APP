import assert from 'node:assert/strict'
import test from 'node:test'
import { createLocalAnswer, normalizeSalesByDate } from '../src/lib/business-assistant-answers.ts'

const summary = {
  business: { name: 'Kitu Households Ventures', ownerName: 'Brian', currency: 'KES', date: '2026-10-28' },
  team: { activeWorkers: 17 },
  attendanceToday: { recordedWorkers: 0, statusCounts: {} },
  payrollThisMonth: { outstanding: 0 },
  salesThisMonth: { records: 4, total: 450 },
  salesByDate: {
    '2025-10-01': { records: 1, total: 125 },
    '2026-10-20': { records: 1, total: 50 },
    '2026-10-26': { records: 1, total: 50 },
    '2026-10-27': { records: 2, total: 350 },
  },
  deductionsThisMonth: {},
  inventory: {},
}

test('plain sales asks about today instead of reusing the monthly total', () => {
  const answer = createLocalAnswer('SALES', summary)
  assert.match(answer, /No sales were recorded for \*\*28 October 2026\*\*\./)
  assert.doesNotMatch(answer, /payroll|attendance|stock|deduction/i)
})

test('today sales use only records dated today', () => {
  const answer = createLocalAnswer('What are today’s sales?', {
    ...summary,
    salesByDate: {
      ...summary.salesByDate,
      '2026-10-28': { records: 1, total: 100 },
    },
  })
  assert.match(answer, /KES 100.*28 October 2026/)
  assert.doesNotMatch(answer, /KES 350/)
})

test('monthly sales are only returned when the question asks for the month', () => {
  assert.match(createLocalAnswer('sales this month', summary), /KES 450/)
})

test('calendar week and rolling date ranges sum only records in the range', () => {
  assert.match(createLocalAnswer('sales this week', summary), /KES 400.*26 October 2026 – 28 October 2026/)
  assert.match(createLocalAnswer('sales over the last 7 days', summary), /KES 400.*22 October 2026 – 28 October 2026/)
  assert.match(createLocalAnswer('sales last week', summary), /KES 50.*19 October 2026 – 25 October 2026/)
  assert.match(createLocalAnswer('sales over the last 30 days', summary), /KES 450.*29 September 2026 – 28 October 2026/)
  assert.match(createLocalAnswer('sales between October 26 and October 27, 2026', summary), /KES 400.*26 October 2026 – 27 October 2026/)
})

test('date ranges support day-first, same-month, and numeric date formats', () => {
  assert.match(createLocalAnswer('sales from 26 to 27 October 2026', summary), /KES 400.*26 October 2026 – 27 October 2026/)
  assert.match(createLocalAnswer('sales from 26 October to 27 October 2026', summary), /KES 400.*26 October 2026 – 27 October 2026/)
  assert.match(createLocalAnswer('sales from 26/10/2026 to 27/10/2026', summary), /KES 400.*26 October 2026 – 27 October 2026/)
  assert.match(createLocalAnswer('sales from 01/10/2025 to 15/10/2025', summary), /KES 125.*1 October 2025 – 15 October 2025/)
  assert.match(createLocalAnswer('sales October 26-27, 2026', summary), /KES 400.*26 October 2026 – 27 October 2026/)
  assert.match(createLocalAnswer('sales from 1 to 15 October 2026', { ...summary, salesByDateFrom: '' }), /No sales were recorded/)
})

test('a later sales question uses its own date, not the date from the previous question', () => {
  const earlierAnswer = createLocalAnswer('sales on 1 October 2025', summary)
  const nextAnswer = createLocalAnswer('sales', summary)
  assert.match(earlierAnswer, /1 October 2025/)
  assert.match(nextAnswer, /28 October 2026/)
  assert.doesNotMatch(nextAnswer, /1 October 2025/)
})

test('a range with no sales clearly reports zero records', () => {
  assert.match(createLocalAnswer('sales last month', { ...summary, salesByDateFrom: '2026-10-20' }), /Sales history.*not available/i)
  assert.match(createLocalAnswer('sales from 1 October to 10 October 2026', { ...summary, salesByDateFrom: '' }), /No sales were recorded/)
})

test('yesterday and explicit day/month dates use their matching records', () => {
  assert.match(createLocalAnswer('sales yesterday', summary), /KES 350.*27 October 2026/)
  assert.match(createLocalAnswer('sales on 27\/10\/2026', summary), /KES 350.*27 October 2026/)
})

test('a date before the included history is reported as unavailable, not zero sales', () => {
  assert.match(createLocalAnswer('sales on 1 January 2020', {
    ...summary,
    salesByDateFrom: '2026-10-27',
  }), /history.*not available/i)
})

test('month-name dates and ISO dates are parsed', () => {
  assert.match(createLocalAnswer('sales for October 27, 2026', summary), /KES 350.*27 October 2026/)
  assert.match(createLocalAnswer('sales on 2026-10-27', summary), /KES 350.*27 October 2026/)
  assert.match(createLocalAnswer('sales on 27\/10', summary), /KES 350.*27 October 2026/)
})

test('invalid date keys are excluded from daily sales', () => {
  assert.deepEqual(normalizeSalesByDate({
    '2026-02-30': { records: 1, total: 10 },
    '2026-10-27': { records: 2, total: 350 },
  }), {
    '2026-10-27': { records: 2, total: 350 },
  })
})
