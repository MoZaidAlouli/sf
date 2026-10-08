-- Security and behaviour tests for supabase/schema.sql.
-- Every check raises an exception on failure; the script stops at the first one.
\set ON_ERROR_STOP on
\echo '== seed: valid submission as service_role'

do $$
declare v_id uuid; v_again uuid; n int;
begin
  set local role service_role;
  v_id := public.submit_registration($j${
    "idempotency_key": "11111111-1111-4111-8111-111111111111",
    "president": {"name": "  Test   President ", "email": "president@example.com"},
    "people": [
      {"full_name": "Amina  Benali", "role_title": "Treasurer", "entity": "Executive Board",
       "responsibilities": "Manages the club budget and receipts.", "access_level": "executive_board",
       "email": "amina@example.com", "notes": null},
      {"full_name": "Youssef El Idrissi", "role_title": "Designer", "entity": "Communication and Media",
       "responsibilities": "Creates posters and social media visuals.", "access_level": "entity_member"}
    ]}$j$::jsonb, 'aaaaaaaaaaaaaaaaaaaaaaaa');
  reset role;
  select count(*) into n from public.registration_submissions;
  if n <> 1 then raise exception 'TEST FAILED: expected 1 submission, got %', n; end if;
  select count(*) into n from public.registration_people where submission_id = v_id;
  if n <> 2 then raise exception 'TEST FAILED: expected 2 people, got %', n; end if;
  if (select president_name from public.registration_submissions where id = v_id) <> 'Test President' then
    raise exception 'TEST FAILED: president name not normalised';
  end if;
  if (select full_name from public.registration_people where submission_id = v_id and position = 1) <> 'Amina Benali' then
    raise exception 'TEST FAILED: person name not normalised';
  end if;
  raise notice 'PASS seed submission stored and normalised';
end $$;

\echo '== idempotency: same key returns same id, no second row'
do $$
declare v_id uuid; v_again uuid; n int;
begin
  select id into v_id from public.registration_submissions limit 1;
  set local role service_role;
  v_again := public.submit_registration($j${
    "idempotency_key": "11111111-1111-4111-8111-111111111111",
    "president": {"name": "Other", "email": "other@example.com"},
    "people": [{"full_name": "Zed Zed", "role_title": "X1", "entity": "Y1",
      "responsibilities": "Does something useful.", "access_level": "member"}]}$j$::jsonb, 'aaaaaaaaaaaaaaaaaaaaaaaa');
  reset role;
  if v_again <> v_id then raise exception 'TEST FAILED: idempotent retry returned a different id'; end if;
  select count(*) into n from public.registration_submissions;
  if n <> 1 then raise exception 'TEST FAILED: idempotent retry created a row'; end if;
  raise notice 'PASS idempotent retry';
end $$;

\echo '== public roles cannot read, write, or call anything'
do $$
declare r text; stmt text;
begin
  foreach r in array array['anon', 'authenticated'] loop
    execute format('set local role %I', r);
    foreach stmt in array array[
      'select * from public.registration_submissions',
      'select * from public.registration_people',
      'select * from public.registration_export',
      $q$insert into public.registration_submissions (idempotency_key, president_name, president_email, people_count, client_hash) values (gen_random_uuid(), 'Aa', 'a@b.co', 1, '0123456789abcdef0123')$q$,
      $q$insert into public.registration_people (submission_id, position, full_name, role_title, entity, responsibilities, access_level) select id, 9, 'Hacker', 'Hx', 'Hx', 'Injected row by anon', 'administrator' from public.registration_submissions$q$,
      $q$update public.registration_submissions set president_name = 'pwned'$q$,
      'delete from public.registration_people',
      'delete from public.registration_submissions',
      $q$select public.submit_registration('{}'::jsonb, 'x')$q$
    ] loop
      begin
        execute stmt;
        raise exception 'TEST FAILED: role % could run: %', r, stmt;
      exception when insufficient_privilege then null;
      end;
    end loop;
    reset role;
  end loop;
  raise notice 'PASS anon/authenticated denied on every table, view and function';
end $$;

\echo '== defense in depth: even with grants, RLS returns no rows and blocks writes'
do $$
declare n int;
begin
  grant select, insert, update, delete on public.registration_submissions, public.registration_people to anon;
  set local role anon;
  select count(*) into n from public.registration_submissions;
  if n <> 0 then raise exception 'TEST FAILED: RLS leaked % rows to anon', n; end if;
  select count(*) into n from public.registration_people;
  if n <> 0 then raise exception 'TEST FAILED: RLS leaked people rows to anon'; end if;
  begin
    insert into public.registration_submissions (idempotency_key, president_name, president_email, people_count, client_hash)
    values (gen_random_uuid(), 'Aa', 'a@b.co', 1, '0123456789abcdef0123');
    raise exception 'TEST FAILED: RLS allowed anon insert';
  exception when insufficient_privilege then null;
  end;
  update public.registration_submissions set president_name = 'pwned';
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'TEST FAILED: RLS allowed anon update'; end if;
  delete from public.registration_submissions;
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'TEST FAILED: RLS allowed anon delete'; end if;
  reset role;
  revoke all on public.registration_submissions, public.registration_people from anon;
  if (select count(*) from public.registration_submissions) <> 1 then raise exception 'TEST FAILED: data changed'; end if;
  raise notice 'PASS RLS blocks reads and writes even if a grant is added by mistake';
end $$;

\echo '== RLS enabled on every table, and there are no policies'
do $$
begin
  if exists (select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity) then
    raise exception 'TEST FAILED: a public table has RLS disabled';
  end if;
  if exists (select 1 from pg_policies where schemaname = 'public') then
    raise exception 'TEST FAILED: unexpected RLS policy exists';
  end if;
  raise notice 'PASS RLS enabled, zero policies';
end $$;

\echo '== invalid payloads are rejected by the database'
do $$
declare stmt text; k int := 0;
begin
  set local role service_role;
  foreach stmt in array array[
    -- missing idempotency key
    $j${"president":{"name":"Ab","email":"a@b.co"},"people":[{"full_name":"Aa Bb","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"member"}]}$j$,
    -- bad president email
    $j${"idempotency_key":"22222222-2222-4222-8222-222222222221","president":{"name":"Ab","email":"nope"},"people":[{"full_name":"Aa Bb","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"member"}]}$j$,
    -- no people
    $j${"idempotency_key":"22222222-2222-4222-8222-222222222222","president":{"name":"Ab","email":"a@b.co"},"people":[]}$j$,
    -- bad access level
    $j${"idempotency_key":"22222222-2222-4222-8222-222222222223","president":{"name":"Ab","email":"a@b.co"},"people":[{"full_name":"Aa Bb","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"superuser"}]}$j$,
    -- responsibilities too short
    $j${"idempotency_key":"22222222-2222-4222-8222-222222222224","president":{"name":"Ab","email":"a@b.co"},"people":[{"full_name":"Aa Bb","role_title":"Rr","entity":"Ee","responsibilities":"short","access_level":"member"}]}$j$,
    -- bad optional person email
    $j${"idempotency_key":"22222222-2222-4222-8222-222222222225","president":{"name":"Ab","email":"a@b.co"},"people":[{"full_name":"Aa Bb","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"member","email":"x@y"}]}$j$,
    -- people is not an array
    $j${"idempotency_key":"22222222-2222-4222-8222-222222222226","president":{"name":"Ab","email":"a@b.co"},"people":"x"}$j$
  ] loop
    k := k + 1;
    begin
      perform public.submit_registration(stmt::jsonb, 'bbbbbbbbbbbbbbbbbbbbbbbb');
      raise exception 'TEST FAILED: invalid payload % was accepted', k;
    exception when sqlstate '22023' then null;
    end;
  end loop;
  reset role;
  if (select count(*) from public.registration_submissions) <> 1 then
    raise exception 'TEST FAILED: an invalid payload left a row behind';
  end if;
  raise notice 'PASS % invalid payloads rejected, nothing stored', k;
end $$;

\echo '== duplicate people are rejected and fully rolled back'
do $$
begin
  set local role service_role;
  begin
    perform public.submit_registration($j${"idempotency_key":"33333333-3333-4333-8333-333333333331","president":{"name":"Ab","email":"a@b.co"},
      "people":[{"full_name":"Same Name","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"member"},
                {"full_name":"same   name","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"member"}]}$j$::jsonb, 'cccccccccccccccccccccccc');
    raise exception 'TEST FAILED: duplicate name accepted';
  exception when unique_violation then null;
  end;
  begin
    perform public.submit_registration($j${"idempotency_key":"33333333-3333-4333-8333-333333333332","president":{"name":"Ab","email":"a@b.co"},
      "people":[{"full_name":"One One","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"member","email":"dup@example.com"},
                {"full_name":"Two Two","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"member","email":"DUP@example.com"}]}$j$::jsonb, 'cccccccccccccccccccccccc');
    raise exception 'TEST FAILED: duplicate email accepted';
  exception when unique_violation then null;
  end;
  reset role;
  if (select count(*) from public.registration_submissions) <> 1 then
    raise exception 'TEST FAILED: duplicate attempt left rows behind';
  end if;
  raise notice 'PASS duplicates rejected, no partial rows';
end $$;

\echo '== rate limiting: 5 per client per hour'
do $$
declare i int; ok boolean := false;
begin
  set local role service_role;
  for i in 1..5 loop
    perform public.submit_registration(format($j${"idempotency_key":"44444444-4444-4444-8444-44444444444%s","president":{"name":"Ab","email":"a@b.co"},
      "people":[{"full_name":"Rate Test","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"member"}]}$j$, i)::jsonb, 'dddddddddddddddddddddddd');
  end loop;
  begin
    perform public.submit_registration($j${"idempotency_key":"44444444-4444-4444-8444-444444444446","president":{"name":"Ab","email":"a@b.co"},
      "people":[{"full_name":"Rate Test","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"member"}]}$j$::jsonb, 'dddddddddddddddddddddddd');
    raise exception 'TEST FAILED: 6th submission from one client was accepted';
  exception when sqlstate 'P0001' then
    if sqlerrm <> 'rate_limited' then raise; end if;
  end;
  -- a different client is unaffected
  perform public.submit_registration($j${"idempotency_key":"44444444-4444-4444-8444-444444444447","president":{"name":"Ab","email":"a@b.co"},
    "people":[{"full_name":"Other Client","role_title":"Rr","entity":"Ee","responsibilities":"Does enough work.","access_level":"member"}]}$j$::jsonb, 'eeeeeeeeeeeeeeeeeeeeeeee');
  reset role;
  raise notice 'PASS rate limit enforced per client';
end $$;

\echo '== table CHECK constraints reject bad rows even for privileged inserts'
do $$
begin
  begin
    insert into public.registration_submissions (idempotency_key, president_name, president_email, people_count, client_hash)
    values (gen_random_uuid(), 'Aa', 'not-an-email', 1, '0123456789abcdef0123');
    raise exception 'TEST FAILED: bad email passed table constraint';
  exception when check_violation then null;
  end;
  begin
    insert into public.registration_people (submission_id, position, full_name, role_title, entity, responsibilities, access_level)
    select id, 5, 'Bad Level', 'Rr', 'Ee', 'Does enough work.', 'root' from public.registration_submissions limit 1;
    raise exception 'TEST FAILED: bad access level passed table constraint';
  exception when check_violation then null;
  end;
  raise notice 'PASS table constraints enforce data rules';
end $$;

\echo '== export view works for the admin (postgres) role'
do $$
declare n int;
begin
  select count(*) into n from public.registration_export;
  if n < 2 then raise exception 'TEST FAILED: export view returned % rows', n; end if;
  raise notice 'PASS export view returns % rows', n;
end $$;

\echo '== ALL DATABASE TESTS PASSED'
