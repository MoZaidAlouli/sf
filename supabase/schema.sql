-- SOUL OS Access Registration: database schema and security policies.
-- Run once in the Supabase SQL Editor (as the default `postgres` role).
--
-- Security model
--   * Row Level Security is ON for every table and NO policies exist, so the
--     public `anon` and `authenticated` roles can never read, insert, update
--     or delete rows, even if a grant is added by mistake.
--   * Table privileges are also revoked from `anon` and `authenticated`.
--   * The only write path is public.submit_registration(), a SECURITY DEFINER
--     function that validates everything, applies rate limits, and is
--     executable ONLY by `service_role`. The Cloudflare Pages Function calls
--     it with the service-role key, which never reaches the browser.
--   * Administrators read data through the authenticated Supabase dashboard.

-- ---------------------------------------------------------------- tables

create table public.registration_submissions (
  id              uuid primary key default gen_random_uuid(),
  created_at      timestamptz not null default now(),
  idempotency_key uuid not null unique,
  president_name  text not null,
  president_email text not null,
  people_count    smallint not null,
  client_hash     text not null,  -- salted SHA-256 of the client IP, for rate limiting only

  constraint president_name_len  check (char_length(btrim(president_name)) between 2 and 120),
  constraint president_email_fmt check (
    char_length(president_email) <= 254
    and president_email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$'
  ),
  constraint people_count_range  check (people_count between 1 and 50),
  constraint client_hash_len     check (char_length(client_hash) between 16 and 128)
);

create index registration_submissions_rate_idx
  on public.registration_submissions (client_hash, created_at desc);
create index registration_submissions_created_idx
  on public.registration_submissions (created_at desc);

create table public.registration_people (
  id               uuid primary key default gen_random_uuid(),
  submission_id    uuid not null references public.registration_submissions (id) on delete cascade,
  position         smallint not null,
  full_name        text not null,
  role_title       text not null,
  entity           text not null,
  responsibilities text not null,
  access_level     text not null,
  email            text,
  notes            text,
  created_at       timestamptz not null default now(),

  constraint position_range     check (position between 1 and 50),
  constraint full_name_len      check (char_length(btrim(full_name)) between 2 and 120),
  constraint role_title_len     check (char_length(btrim(role_title)) between 2 and 120),
  constraint entity_len         check (char_length(btrim(entity)) between 2 and 120),
  constraint responsibilities_len check (char_length(btrim(responsibilities)) between 10 and 2000),
  constraint access_level_enum  check (access_level in (
    'member', 'entity_member', 'entity_leader', 'executive_board',
    'digital_entity', 'administrator', 'to_be_determined'
  )),
  constraint person_email_fmt   check (
    email is null or (
      char_length(email) <= 254
      and email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$'
    )
  ),
  constraint notes_len          check (notes is null or char_length(notes) <= 1000)
);

create index registration_people_submission_idx on public.registration_people (submission_id);

-- No duplicate people inside one submission (same name, or same email).
create unique index registration_people_name_uniq
  on public.registration_people (submission_id, lower(regexp_replace(btrim(full_name), '\s+', ' ', 'g')));
create unique index registration_people_email_uniq
  on public.registration_people (submission_id, lower(email))
  where email is not null;

-- ---------------------------------------------------------- RLS + grants

alter table public.registration_submissions enable row level security;
alter table public.registration_people      enable row level security;
-- Intentionally NO policies: with RLS enabled, non-privileged roles get zero access.

revoke all on public.registration_submissions from anon, authenticated;
revoke all on public.registration_people      from anon, authenticated;

-- ------------------------------------------------------- submit function

create or replace function public.submit_registration(payload jsonb, p_client_hash text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  c_email         constant text := '^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$';
  c_per_client    constant int  := 5;   -- submissions per client per hour
  c_global        constant int  := 60;  -- submissions overall per hour
  v_key           uuid;
  v_id            uuid;
  v_name          text;
  v_email         text;
  v_people        jsonb;
  v_count         int;
  p               record;
  v_pname         text;
  v_role          text;
  v_entity        text;
  v_resp          text;
  v_level         text;
  v_pemail        text;
  v_notes         text;
begin
  if payload is null
     or coalesce(jsonb_typeof(payload), '') <> 'object'
     or coalesce(jsonb_typeof(payload -> 'president'), '') <> 'object'
     or coalesce(jsonb_typeof(payload -> 'people'), '') <> 'array' then
    raise exception 'invalid: malformed payload' using errcode = '22023';
  end if;

  if p_client_hash is null or char_length(p_client_hash) not between 16 and 128 then
    raise exception 'invalid: missing client reference' using errcode = '22023';
  end if;

  -- Idempotency: a retry of an already-saved submission returns the same id.
  begin
    v_key := (payload ->> 'idempotency_key')::uuid;
  exception when invalid_text_representation then
    v_key := null;
  end;
  if v_key is null then
    raise exception 'invalid: missing submission key' using errcode = '22023';
  end if;
  select id into v_id from public.registration_submissions where idempotency_key = v_key;
  if v_id is not null then
    return v_id;
  end if;

  -- Rate limiting.
  if (select count(*) from public.registration_submissions
        where client_hash = p_client_hash and created_at > now() - interval '1 hour') >= c_per_client
     or (select count(*) from public.registration_submissions
        where created_at > now() - interval '1 hour') >= c_global then
    raise exception 'rate_limited' using errcode = 'P0001';
  end if;

  -- President.
  v_name  := regexp_replace(btrim(coalesce(payload -> 'president' ->> 'name', '')), '\s+', ' ', 'g');
  v_email := btrim(coalesce(payload -> 'president' ->> 'email', ''));
  if char_length(v_name) not between 2 and 120 then
    raise exception 'invalid: president name must be 2 to 120 characters' using errcode = '22023';
  end if;
  if char_length(v_email) > 254 or v_email !~ c_email then
    raise exception 'invalid: president email is not valid' using errcode = '22023';
  end if;

  v_people := payload -> 'people';
  v_count  := jsonb_array_length(v_people);
  if v_count not between 1 and 50 then
    raise exception 'invalid: between 1 and 50 people are required' using errcode = '22023';
  end if;

  insert into public.registration_submissions
    (idempotency_key, president_name, president_email, people_count, client_hash)
  values (v_key, v_name, v_email, v_count, p_client_hash)
  returning id into v_id;

  for p in
    select t.value as person, t.ord
    from jsonb_array_elements(v_people) with ordinality as t(value, ord)
  loop
    if coalesce(jsonb_typeof(p.person), '') <> 'object' then
      raise exception 'invalid: person % is malformed', p.ord using errcode = '22023';
    end if;

    v_pname  := regexp_replace(btrim(coalesce(p.person ->> 'full_name', '')), '\s+', ' ', 'g');
    v_role   := regexp_replace(btrim(coalesce(p.person ->> 'role_title', '')), '\s+', ' ', 'g');
    v_entity := regexp_replace(btrim(coalesce(p.person ->> 'entity', '')), '\s+', ' ', 'g');
    v_resp   := btrim(coalesce(p.person ->> 'responsibilities', ''));
    v_level  := coalesce(p.person ->> 'access_level', '');
    v_pemail := nullif(btrim(coalesce(p.person ->> 'email', '')), '');
    v_notes  := nullif(btrim(coalesce(p.person ->> 'notes', '')), '');

    if char_length(v_pname) not between 2 and 120 then
      raise exception 'invalid: person % full name must be 2 to 120 characters', p.ord using errcode = '22023';
    end if;
    if char_length(v_role) not between 2 and 120 then
      raise exception 'invalid: person % role must be 2 to 120 characters', p.ord using errcode = '22023';
    end if;
    if char_length(v_entity) not between 2 and 120 then
      raise exception 'invalid: person % entity must be 2 to 120 characters', p.ord using errcode = '22023';
    end if;
    if char_length(v_resp) not between 10 and 2000 then
      raise exception 'invalid: person % responsibilities must be 10 to 2000 characters', p.ord using errcode = '22023';
    end if;
    if v_level not in ('member', 'entity_member', 'entity_leader', 'executive_board',
                       'digital_entity', 'administrator', 'to_be_determined') then
      raise exception 'invalid: person % access level is not valid', p.ord using errcode = '22023';
    end if;
    if v_pemail is not null and (char_length(v_pemail) > 254 or v_pemail !~ c_email) then
      raise exception 'invalid: person % email is not valid', p.ord using errcode = '22023';
    end if;
    if v_notes is not null and char_length(v_notes) > 1000 then
      raise exception 'invalid: person % notes are too long', p.ord using errcode = '22023';
    end if;

    -- A duplicate name or email within the submission raises unique_violation (23505).
    insert into public.registration_people
      (submission_id, position, full_name, role_title, entity, responsibilities,
       access_level, email, notes)
    values
      (v_id, p.ord, v_pname, v_role, v_entity, v_resp, v_level, v_pemail, v_notes);
  end loop;

  return v_id;
end;
$$;

revoke all on function public.submit_registration(jsonb, text) from public, anon, authenticated;
grant execute on function public.submit_registration(jsonb, text) to service_role;

-- ------------------------------------------------------------ CSV export

-- One row per person, with the submission details attached.
-- In the dashboard: SQL Editor -> `select * from public.registration_export;`
-- -> "Download CSV" (or Table Editor -> the view -> Export).
create or replace view public.registration_export
with (security_invoker = true) as
select
  s.id               as submission_id,
  s.created_at       as submitted_at,
  s.president_name,
  s.president_email,
  p.position         as person_number,
  p.full_name,
  p.role_title,
  p.entity,
  p.access_level,
  p.responsibilities,
  p.email            as person_email,
  p.notes
from public.registration_submissions s
join public.registration_people p on p.submission_id = s.id
order by s.created_at desc, p.position;

revoke all on public.registration_export from anon, authenticated;
