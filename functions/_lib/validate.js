// Server-side validation and normalisation. Mirrors the rules enforced again
// in the database (supabase/schema.sql), so a bypassed browser check still fails.

export const ACCESS_LEVELS = [
  'member',
  'entity_member',
  'entity_leader',
  'executive_board',
  'digital_entity',
  'administrator',
  'to_be_determined',
];
export const MAX_PEOPLE = 50;

const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

const line = (v) => (typeof v === 'string' ? v.replace(CONTROL, '').replace(/\s+/g, ' ').trim() : '');
const block = (v) =>
  typeof v === 'string' ? v.replace(/\r\n?/g, '\n').replace(CONTROL, '').trim() : '';

const between = (s, min, max) => s.length >= min && s.length <= max;

export function validateSubmission(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, error: 'Malformed submission.' };
  }
  if (typeof body.idempotency_key !== 'string' || !UUID_RE.test(body.idempotency_key)) {
    return { ok: false, error: 'Malformed submission.' };
  }

  const pres = body.president;
  if (!pres || typeof pres !== 'object') return { ok: false, error: 'Malformed submission.' };
  const president = { name: line(pres.name), email: line(pres.email) };
  if (!between(president.name, 2, 120)) {
    return { ok: false, error: "President's name must be 2 to 120 characters." };
  }
  if (president.email.length > 254 || !EMAIL_RE.test(president.email)) {
    return { ok: false, error: "President's email address is not valid." };
  }

  if (!Array.isArray(body.people) || body.people.length < 1 || body.people.length > MAX_PEOPLE) {
    return { ok: false, error: `Add between 1 and ${MAX_PEOPLE} people.` };
  }

  const people = [];
  const seenNames = new Map();
  const seenEmails = new Map();
  for (let i = 0; i < body.people.length; i++) {
    const n = i + 1;
    const raw = body.people[i];
    if (!raw || typeof raw !== 'object') return { ok: false, error: `Person ${n} is malformed.` };

    const person = {
      full_name: line(raw.full_name),
      role_title: line(raw.role_title),
      entity: line(raw.entity),
      responsibilities: block(raw.responsibilities),
      access_level: typeof raw.access_level === 'string' ? raw.access_level : '',
      email: line(raw.email) || null,
      notes: block(raw.notes) || null,
    };

    if (!between(person.full_name, 2, 120)) return { ok: false, error: `Person ${n}: full name must be 2 to 120 characters.` };
    if (!between(person.role_title, 2, 120)) return { ok: false, error: `Person ${n}: role must be 2 to 120 characters.` };
    if (!between(person.entity, 2, 120)) return { ok: false, error: `Person ${n}: entity or department must be 2 to 120 characters.` };
    if (!between(person.responsibilities, 10, 2000)) return { ok: false, error: `Person ${n}: responsibilities must be 10 to 2000 characters.` };
    if (!ACCESS_LEVELS.includes(person.access_level)) return { ok: false, error: `Person ${n}: choose a valid access level.` };
    if (person.email && (person.email.length > 254 || !EMAIL_RE.test(person.email))) return { ok: false, error: `Person ${n}: email address is not valid.` };
    if (person.notes && person.notes.length > 1000) return { ok: false, error: `Person ${n}: notes must be 1000 characters or fewer.` };

    const nameKey = person.full_name.toLowerCase();
    if (seenNames.has(nameKey)) return { ok: false, error: `Person ${n} duplicates person ${seenNames.get(nameKey)}.` };
    seenNames.set(nameKey, n);
    if (person.email) {
      const emailKey = person.email.toLowerCase();
      if (seenEmails.has(emailKey)) return { ok: false, error: `Person ${n} duplicates person ${seenEmails.get(emailKey)}.` };
      seenEmails.set(emailKey, n);
    }
    people.push(person);
  }

  return { ok: true, value: { idempotency_key: body.idempotency_key.toLowerCase(), president, people } };
}
