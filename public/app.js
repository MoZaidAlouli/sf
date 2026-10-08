(() => {
  'use strict';

  // ---- Configuration -------------------------------------------------------
  // Edit this list to match the real SOUL entities. Visitors can also type their own.
  const ENTITIES = [
    'Executive Board',
    'Communication and Media',
    'Events and Logistics',
    'Partnerships and Fundraising',
    'Humanitarian Actions',
    'Digital Entity',
  ];

  const ACCESS = [
    { value: 'member', label: 'Member', desc: 'A SOUL member who needs standard access to shared club spaces.' },
    { value: 'entity_member', label: 'Entity Member', desc: "Belongs to one entity and works inside that entity's space." },
    { value: 'entity_leader', label: 'Entity Leader', desc: "Leads an entity and coordinates its members and work." },
    { value: 'executive_board', label: 'Executive Board', desc: 'Sits on the executive board and needs visibility across entities.' },
    { value: 'digital_entity', label: 'Digital Entity', desc: 'Configures SOUL OS, including accounts and permissions.' },
    { value: 'administrator', label: 'Administrator', desc: 'Full control over SOUL OS settings and data. Keep this to very few people.' },
    { value: 'to_be_determined', label: 'To be determined', desc: 'Not sure yet. The Digital Entity will follow up with the president.' },
  ];

  const OTHER = '__other';
  const MAX_PEOPLE = 50;
  const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;
  const SUBMIT_TIMEOUT_MS = 20000;
  const PERSON_FIELDS = ['full_name', 'role_title', 'entity', 'responsibilities', 'access_level', 'email', 'notes'];
  const STEP_TITLES = { 1: 'Your details', 2: 'People who need access', 3: 'Review before you submit' };

  // ---- Helpers -------------------------------------------------------------
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const clean = (s) => String(s || '').replace(/\s+/g, ' ').trim();
  const cleanBlock = (s) => String(s || '').replace(/\r\n?/g, '\n').trim();

  function uuid() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID();
    const b = new Uint8Array(16);
    window.crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  // ---- Elements ------------------------------------------------------------
  const form = $('#form');
  const panels = $$('[data-step]', form);
  const indicators = $$('[data-step-indicator]');
  const peopleBox = $('#people');
  const tpl = $('#person-tpl');
  const addBtn = $('#add-person');
  const submitBtn = $('#submit-btn');
  const submitError = $('#submit-error');
  const live = $('#live');
  const confirmation = $('#confirmation');
  const presidentScope = $('[data-step="1"]', form);

  // ---- State ---------------------------------------------------------------
  let step = 1;
  let uid = 0;
  let dirty = false;
  let submitting = false;
  let submitted = false;
  let idemKey = null;
  let turnstileToken = '';
  let turnstileWidget = null;
  let turnstileOn = false;

  const announce = (msg) => {
    live.textContent = '';
    live.textContent = msg;
  };

  // ---- Validation ----------------------------------------------------------
  const len = (v, min, max, msgRange) => (v.length < min || v.length > max ? msgRange : '');

  const rules = {
    president_name: (v) => (!v ? "Enter the president's full name." : len(v, 2, 120, 'Use 2 to 120 characters.')),
    president_email: (v) =>
      !v ? "Enter the president's email address." : v.length > 254 || !EMAIL_RE.test(v) ? 'Enter a valid email address, such as name@example.com.' : '',
    full_name: (v) => (!v ? "Enter the person's full name." : len(v, 2, 120, 'Use 2 to 120 characters.')),
    role_title: (v) => (!v ? "Enter the person's role in SOUL." : len(v, 2, 120, 'Use 2 to 120 characters.')),
    entity: (v, ctx) =>
      !v ? (ctx && ctx.other ? 'Type the entity or department.' : 'Choose an entity or department.') : len(v, 2, 120, 'Use 2 to 120 characters.'),
    responsibilities: (v) =>
      !v ? 'Describe the main responsibilities.' : v.length < 10 ? 'Add a little more detail (at least 10 characters).' : v.length > 2000 ? 'Keep this under 2000 characters.' : '',
    access_level: (v) => (ACCESS.some((a) => a.value === v) ? '' : 'Choose a suggested access level.'),
    email: (v) => (v && (v.length > 254 || !EMAIL_RE.test(v)) ? 'Enter a valid email address, such as name@example.com.' : ''),
    notes: (v) => (v.length > 1000 ? 'Keep notes under 1000 characters.' : ''),
  };

  const fieldInput = (scope, name) => $(`[data-input="${name}"]`, scope);
  const fieldWrap = (scope, name) => $(`[data-field="${name}"]`, scope);

  function readPresident() {
    return {
      president_name: clean(fieldInput(presidentScope, 'president_name').value),
      president_email: clean(fieldInput(presidentScope, 'president_email').value),
    };
  }

  function readPerson(el) {
    const sel = fieldInput(el, 'entity').value;
    return {
      full_name: clean(fieldInput(el, 'full_name').value),
      role_title: clean(fieldInput(el, 'role_title').value),
      entity: sel === OTHER ? clean(fieldInput(el, 'entity_custom').value) : sel,
      responsibilities: cleanBlock(fieldInput(el, 'responsibilities').value),
      access_level: fieldInput(el, 'access_level').value,
      email: clean(fieldInput(el, 'email').value),
      notes: cleanBlock(fieldInput(el, 'notes').value),
    };
  }

  function showError(scope, name, msg) {
    const wrap = fieldWrap(scope, name);
    const err = $('[data-err]', wrap);
    wrap.classList.toggle('has-error', Boolean(msg));
    err.textContent = msg || '';
    err.hidden = !msg;
    $$('input, select, textarea', wrap).forEach((c) => {
      if (msg) c.setAttribute('aria-invalid', 'true');
      else c.removeAttribute('aria-invalid');
    });
  }

  function firstFocusable(scope, name) {
    const wrap = fieldWrap(scope, name);
    if (name === 'entity') {
      const custom = fieldInput(scope, 'entity_custom');
      return custom.hidden ? fieldInput(scope, 'entity') : custom;
    }
    return $('input, select, textarea', wrap);
  }

  // Returns the message (and shows it). `values` is the object from readPerson/readPresident.
  function checkField(scope, name, values) {
    const ctx = name === 'entity' ? { other: fieldInput(scope, 'entity').value === OTHER } : undefined;
    const msg = rules[name](values[name], ctx);
    showError(scope, name, msg);
    return msg;
  }

  function validateStep1() {
    const vals = readPresident();
    let first = null;
    ['president_name', 'president_email'].forEach((n) => {
      if (checkField(presidentScope, n, vals) && !first) first = firstFocusable(presidentScope, n);
    });
    if (first) {
      first.focus();
      announce('Fix the highlighted fields to continue.');
      return false;
    }
    return true;
  }

  function validateStep2() {
    const els = people();
    let first = null;
    let count = 0;
    const seenNames = new Map();
    const seenEmails = new Map();

    els.forEach((el, i) => {
      const vals = readPerson(el);
      PERSON_FIELDS.forEach((n) => {
        const msg = checkField(el, n, vals);
        if (msg) {
          count += 1;
          if (!first) first = firstFocusable(el, n);
        }
      });
      // Duplicates within this submission.
      if (vals.full_name.length >= 2) {
        const key = vals.full_name.toLowerCase();
        if (seenNames.has(key)) {
          showError(el, 'full_name', `This person already appears above as Person ${seenNames.get(key)}.`);
          count += 1;
          if (!first) first = fieldInput(el, 'full_name');
        } else seenNames.set(key, i + 1);
      }
      if (vals.email && EMAIL_RE.test(vals.email)) {
        const key = vals.email.toLowerCase();
        if (seenEmails.has(key)) {
          showError(el, 'email', `This email already appears above for Person ${seenEmails.get(key)}.`);
          count += 1;
          if (!first) first = fieldInput(el, 'email');
        } else seenEmails.set(key, i + 1);
      }
    });

    if (first) {
      first.focus();
      announce(`${count} ${count === 1 ? 'field needs' : 'fields need'} attention.`);
      return false;
    }
    return true;
  }

  // ---- People --------------------------------------------------------------
  const people = () => $$('.person', peopleBox);

  function populateSelects(el) {
    const entity = fieldInput(el, 'entity');
    entity.append(new Option('Select an entity or department', ''));
    ENTITIES.forEach((e) => entity.append(new Option(e, e)));
    entity.append(new Option('Other (type your own)', OTHER));

    const level = fieldInput(el, 'access_level');
    level.append(new Option('Select an access level', ''));
    ACCESS.forEach((a) => level.append(new Option(a.label, a.value)));
  }

  function setupPerson(el, id) {
    populateSelects(el);
    $$('[data-input]', el).forEach((inp) => {
      inp.id = `p${id}-${inp.dataset.input}`;
    });
    $$('label[data-for]', el).forEach((lab) => {
      lab.htmlFor = `p${id}-${lab.dataset.for}`;
    });
    $$('[data-err]', el).forEach((err) => {
      err.id = `p${id}-${err.dataset.err}-err`;
    });
    const desc = $('[data-desc="access_level"]', el);
    desc.id = `p${id}-access_level-desc`;

    PERSON_FIELDS.forEach((n) => {
      const err = $(`[data-err="${n}"]`, el);
      const ids = [err.id];
      if (n === 'access_level') ids.push(desc.id);
      fieldWrap(el, n)
        .querySelectorAll('input, select, textarea')
        .forEach((c) => c.setAttribute('aria-describedby', ids.join(' ')));
    });
    updateLevelDesc(el);
  }

  function updateLevelDesc(el) {
    const v = fieldInput(el, 'access_level').value;
    const found = ACCESS.find((a) => a.value === v);
    $('[data-desc="access_level"]', el).textContent = found
      ? found.desc
      : 'Choose the closest match. If you are not sure, pick To be determined.';
  }

  function renumber() {
    const els = people();
    els.forEach((el, i) => {
      $('.person-label', el).textContent = `Person ${i + 1}`;
      const rm = $('[data-action="remove"]', el);
      rm.hidden = els.length === 1;
      rm.setAttribute('aria-label', `Remove person ${i + 1}`);
      rm.textContent = 'Remove this person';
      delete rm.dataset.confirm;
    });
    addBtn.disabled = els.length >= MAX_PEOPLE;
  }

  function addPerson(focus = true) {
    if (people().length >= MAX_PEOPLE) {
      announce(`You can add up to ${MAX_PEOPLE} people in one submission.`);
      return null;
    }
    uid += 1;
    const el = tpl.content.firstElementChild.cloneNode(true);
    setupPerson(el, uid);
    peopleBox.append(el);
    renumber();
    idemKey = null;
    if (focus) {
      fieldInput(el, 'full_name').focus();
      announce(`${$('.person-label', el).textContent} added.`);
    }
    return el;
  }

  function hasData(el) {
    const v = readPerson(el);
    return Object.values(v).some(Boolean);
  }

  function removePerson(el, btn) {
    if (people().length <= 1) return;
    if (hasData(el) && btn.dataset.confirm !== '1') {
      btn.dataset.confirm = '1';
      btn.textContent = 'Select again to confirm removal';
      setTimeout(() => {
        if (btn.isConnected && btn.dataset.confirm === '1') {
          delete btn.dataset.confirm;
          btn.textContent = 'Remove this person';
        }
      }, 5000);
      return;
    }
    const all = people();
    const idx = all.indexOf(el);
    el.remove();
    renumber();
    idemKey = null;
    const rest = people();
    const target = rest[Math.min(idx, rest.length - 1)];
    fieldInput(target, 'full_name').focus();
    announce('Person removed.');
  }

  // Delegated events for the people list.
  peopleBox.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="remove"]');
    if (btn) removePerson(btn.closest('.person'), btn);
  });

  peopleBox.addEventListener('change', (e) => {
    const el = e.target.closest('.person');
    if (!el) return;
    const name = e.target.dataset.input;
    if (name === 'entity') {
      const other = e.target.value === OTHER;
      const custom = fieldInput(el, 'entity_custom');
      custom.hidden = !other;
      if (other) custom.focus();
      else custom.value = '';
    }
    if (name === 'access_level') updateLevelDesc(el);
  });

  // Touched-field validation: validate on blur once the person has typed, clear on fix.
  function attachFieldValidation(root, scopeOf, nameOf) {
    root.addEventListener('input', (e) => {
      const scope = scopeOf(e.target);
      if (!scope) return;
      e.target.dataset.touched = '1';
      const name = nameOf(e.target);
      if (name && fieldWrap(scope, name).classList.contains('has-error')) {
        revalidate(scope, name);
      }
    });
    root.addEventListener('focusout', (e) => {
      const scope = scopeOf(e.target);
      if (!scope || !e.target.dataset || !e.target.dataset.touched) return;
      const name = nameOf(e.target);
      if (name) revalidate(scope, name);
    });
  }

  function revalidate(scope, name) {
    const vals = scope === presidentScope ? readPresident() : readPerson(scope);
    checkField(scope, name, vals);
  }

  const personName = (t) => {
    const n = t.dataset && t.dataset.input;
    return n === 'entity_custom' ? 'entity' : n;
  };
  attachFieldValidation(peopleBox, (t) => t.closest && t.closest('.person'), personName);
  attachFieldValidation(presidentScope, (t) => (t.dataset && t.dataset.input ? presidentScope : null), (t) => t.dataset.input);

  // ---- Steps ---------------------------------------------------------------
  function showStep(n, focus = true) {
    step = n;
    panels.forEach((p) => {
      p.hidden = Number(p.dataset.step) !== n;
    });
    indicators.forEach((li) => {
      const i = Number(li.dataset.stepIndicator);
      li.classList.toggle('is-current', i === n);
      li.classList.toggle('is-done', i < n);
      if (i === n) li.setAttribute('aria-current', 'step');
      else li.removeAttribute('aria-current');
    });
    if (n === 3) renderReview();
    submitError.hidden = true;
    announce(`Step ${n} of 3: ${STEP_TITLES[n]}`);
    if (focus) {
      const heading = $('h2', $(`[data-step="${n}"]`, form));
      heading.focus({ preventScroll: true });
      const steps = $('#steps');
      if (steps.scrollIntoView) steps.scrollIntoView({ block: 'start' });
    }
  }

  $('#to-step2').addEventListener('click', () => {
    if (validateStep1()) showStep(2);
  });
  $('#back-to-1').addEventListener('click', () => showStep(1));
  $('#to-step3').addEventListener('click', () => {
    if (validateStep2()) showStep(3);
  });
  $('#back-to-2').addEventListener('click', () => showStep(2));
  addBtn.addEventListener('click', () => addPerson(true));

  // ---- Review --------------------------------------------------------------
  function dl(rows) {
    const d = document.createElement('dl');
    rows.forEach(([k, v]) => {
      const dt = document.createElement('dt');
      dt.textContent = k;
      const dd = document.createElement('dd');
      dd.textContent = v;
      d.append(dt, dd);
    });
    return d;
  }

  function renderReview() {
    const box = $('#review');
    box.textContent = '';
    const pres = readPresident();

    const pBox = document.createElement('div');
    pBox.className = 'review-president';
    pBox.append(
      dl([
        ['President', pres.president_name],
        ['Email', pres.president_email],
        ['Submission date', $('#submission-date').textContent],
      ]),
    );
    box.append(pBox);

    people().forEach((el, i) => {
      const v = readPerson(el);
      const art = document.createElement('article');
      art.className = 'review-person';
      const h = document.createElement('h3');
      const title = document.createElement('span');
      title.textContent = `${i + 1}. ${v.full_name}`;
      const edit = document.createElement('button');
      edit.type = 'button';
      edit.className = 'btn-edit';
      edit.textContent = 'Edit';
      edit.setAttribute('aria-label', `Edit ${v.full_name}`);
      edit.addEventListener('click', () => {
        showStep(2, false);
        el.classList.add('flash');
        setTimeout(() => el.classList.remove('flash'), 1300);
        if (el.scrollIntoView) el.scrollIntoView({ block: 'center' });
        fieldInput(el, 'full_name').focus({ preventScroll: true });
      });
      h.append(title, edit);
      const level = ACCESS.find((a) => a.value === v.access_level);
      art.append(
        h,
        dl([
          ['Role', v.role_title],
          ['Entity or department', v.entity],
          ['Suggested access', level ? level.label : v.access_level],
          ['Responsibilities', v.responsibilities],
          ['Email', v.email || 'Not provided'],
          ['Notes', v.notes || 'None'],
        ]),
      );
      box.append(art);
    });
  }

  // ---- Submit --------------------------------------------------------------
  function setBusy(on) {
    submitting = on;
    submitBtn.disabled = on;
    if (on) {
      submitBtn.setAttribute('aria-busy', 'true');
      submitBtn.textContent = 'Submitting';
    } else {
      submitBtn.removeAttribute('aria-busy');
      submitBtn.textContent = 'Submit registration';
    }
  }

  function showSubmitError(msg) {
    submitError.textContent = msg;
    submitError.hidden = false;
  }

  function buildPayload() {
    const pres = readPresident();
    if (!idemKey) idemKey = uuid();
    return {
      idempotency_key: idemKey,
      president: { name: pres.president_name, email: pres.president_email },
      people: people().map((el) => {
        const v = readPerson(el);
        return {
          full_name: v.full_name,
          role_title: v.role_title,
          entity: v.entity,
          responsibilities: v.responsibilities,
          access_level: v.access_level,
          email: v.email || null,
          notes: v.notes || null,
        };
      }),
      website: $('#website').value,
      turnstile_token: turnstileToken || undefined,
    };
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (submitting || submitted) return;

    // Re-validate everything; send the person back to whichever step has a problem.
    if (!validateStep1()) return showStep(1);
    if (!validateStep2()) return showStep(2);
    if (step !== 3) return showStep(3);
    if (turnstileOn && !turnstileToken) {
      showSubmitError('Complete the verification check above, then submit again.');
      return;
    }

    submitError.hidden = true;
    setBusy(true);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SUBMIT_TIMEOUT_MS);
    let ok = false;
    try {
      const res = await fetch('/api/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(buildPayload()),
        signal: controller.signal,
      });
      let data = {};
      try {
        data = await res.json();
      } catch {
        /* non-JSON error body */
      }
      if (res.ok && data.ok === true) {
        ok = true;
      } else {
        showSubmitError(data.error || 'Something went wrong while saving. Your answers are still here, so you can try again.');
        if (data.code === 'verification_failed' || data.code === 'rate_limited') resetTurnstile();
      }
    } catch (err) {
      showSubmitError(
        err && err.name === 'AbortError'
          ? 'The request took too long. Your answers are still here. Check your connection and try again.'
          : 'We could not reach the server. Your answers are still here. Check your connection and try again.',
      );
    } finally {
      clearTimeout(timer);
    }

    if (ok) return finish();
    setBusy(false);
    resetTurnstile();
  });

  function finish() {
    submitted = true;
    dirty = false;
    // Drop everything from the page: nothing sensitive stays in the DOM.
    peopleBox.textContent = '';
    $('#review').textContent = '';
    form.reset();
    form.hidden = true;
    $('#steps').hidden = true;
    confirmation.hidden = false;
    $('h2', confirmation).focus({ preventScroll: true });
    if (confirmation.scrollIntoView) confirmation.scrollIntoView({ block: 'start' });
    announce('Submission received.');
  }

  // ---- Turnstile (optional) --------------------------------------------------
  function resetTurnstile() {
    turnstileToken = '';
    if (turnstileOn && window.turnstile && turnstileWidget !== null) window.turnstile.reset(turnstileWidget);
  }

  function loadTurnstile(siteKey) {
    turnstileOn = true;
    window.onTurnstileLoad = () => {
      turnstileWidget = window.turnstile.render('#turnstile', {
        sitekey: siteKey,
        callback: (t) => {
          turnstileToken = t;
        },
        'expired-callback': () => {
          turnstileToken = '';
        },
        'error-callback': () => {
          turnstileToken = '';
        },
      });
    };
    const s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onTurnstileLoad';
    s.async = true;
    s.defer = true;
    document.head.append(s);
  }

  async function loadConfig() {
    try {
      const res = await fetch('/api/config');
      if (!res.ok) return;
      const cfg = await res.json();
      if (cfg && cfg.turnstileSiteKey) loadTurnstile(cfg.turnstileSiteKey);
    } catch {
      /* The server enforces verification if it is configured. */
    }
  }

  // ---- Init ------------------------------------------------------------------
  $('#submission-date').textContent = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

  const levelsList = $('#levels-list');
  ACCESS.forEach((a) => {
    const dt = document.createElement('dt');
    dt.textContent = a.label;
    const dd = document.createElement('dd');
    dd.textContent = a.desc;
    levelsList.append(dt, dd);
  });

  form.addEventListener('input', () => {
    dirty = true;
    idemKey = null; // any edit means a new submission, never a replay of an earlier one
  });
  window.addEventListener('beforeunload', (e) => {
    if (dirty && !submitted) {
      e.preventDefault();
      e.returnValue = '';
    }
  });

  addPerson(false);
  showStep(1, false);
  loadConfig();
})();
