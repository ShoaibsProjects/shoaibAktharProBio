export const DASHBOARD_TIME_ZONE = 'America/Chicago';

const displayDate = new Intl.DateTimeFormat('en-CA', {
  timeZone: DASHBOARD_TIME_ZONE, year: 'numeric', month: '2-digit', day: '2-digit'
});
const localHour = new Intl.DateTimeFormat('en-US', {
  timeZone: DASHBOARD_TIME_ZONE, hour: '2-digit', hourCycle: 'h23'
});
const hour = 60 * 60 * 1000;
const day = 24 * hour;

export function centralDate(now) {
  const fields = Object.fromEntries(displayDate.formatToParts(now).map(({ type, value }) => [type, value]));
  return fields.year + '-' + fields.month + '-' + fields.day;
}

function isoDate(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

function sqlMidnight(date) {
  // 06:00 UTC is midnight CST or 1 AM CDT, before either DST change.
  const probe = new Date(date + 'T06:00:00Z');
  const midnight = new Date(probe.getTime() - Number(localHour.format(probe)) * hour);
  return midnight.toISOString().slice(0, 19).replace('T', ' ');
}

export function centralDayRange(date) {
  if (!/^[2]\d{3}-\d{2}-\d{2}$/.test(date)) return null;
  const time = Date.parse(date + 'T00:00:00Z');
  if (!Number.isFinite(time) || isoDate(time) !== date) return null;
  return { date, start: sqlMidnight(date), end: sqlMidnight(isoDate(time + day)) };
}

export function centralCalendar(now, length) {
  const time = Date.parse(centralDate(now) + 'T00:00:00Z');
  const boundaries = Array.from({ length: length + 1 }, (_, i) => {
    const date = isoDate(time + (i - length + 1) * day);
    return { date, start: sqlMidnight(date) };
  });
  return boundaries.slice(0, -1).map((boundary, i) => ({ ...boundary, end: boundaries[i + 1].start }));
}
