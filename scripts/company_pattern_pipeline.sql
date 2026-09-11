-- ---- Stage 1: filter to verified personal-looking rows ----
CREATE OR REPLACE TEMP TABLE f_verified AS
SELECT
  index_domain(domain) AS dom,
  lower(split_part(split_part(email, '@', 1), '+', 1)) AS lp,   -- localpart, +tag stripped, dots kept
  full_name, title, seniority
FROM c.contacts
WHERE is_verified = TRUE
  AND email IS NOT NULL AND length(trim(email)) > 0 AND email LIKE '%@%'
  AND full_name IS NOT NULL AND length(trim(full_name)) > 0
  AND domain IS NOT NULL AND length(trim(domain)) > 0;

-- ---- Stage 2: drop role/generic localparts (stoplist §4) ----
CREATE OR REPLACE TEMP TABLE f_personal AS
SELECT * FROM f_verified
WHERE lp NOT IN ('info','support','sales','admin','contact','hello','help','team',
  'office','hr','jobs','careers','billing','accounts','no-reply','noreply','do-not-reply',
  'marketing','press','media','legal','privacy','security','abuse','postmaster','webmaster',
  'customercare','customer.care','service','enquiries','inquiries','general')
  AND NOT regexp_matches(lp, '^(mail|email|test)');

-- ---- Stage 3: parse name tokens + normalize; require first & last present ----
CREATE OR REPLACE TEMP TABLE f_named AS
SELECT * FROM (
  SELECT dom, lp, title, seniority,
         name_first(full_name) AS first, name_last(full_name) AS last,
         name_is_mononym(full_name) AS mononym
  FROM f_personal
)
WHERE length(first) > 0 AND length(last) > 0;

-- ---- Stage 4: dedupe to one row per (domain, localpart) §1 ----
CREATE OR REPLACE TEMP TABLE dedup AS
SELECT dom, lp, first, last, title, seniority, mononym
FROM f_named
QUALIFY row_number() OVER (
  PARTITION BY dom, lp ORDER BY first, last, title, seniority, mononym
) = 1;

-- ---- Stage 5: match localpart against the 15 templates; keep EXACTLY one ----
CREATE OR REPLACE TEMP TABLE resolved AS
SELECT dom, role, hits[1].id AS pattern
FROM (
  SELECT dom,
    role_of(title, seniority) AS role,
    list_filter([
      {'id':'P01','t': first},
      {'id':'P02','t': last},
      {'id':'P03','t': first || last},
      {'id':'P04','t': first || '.' || last},
      {'id':'P05','t': left(first,1) || last},
      {'id':'P06','t': left(first,1) || '.' || last},
      {'id':'P07','t': first || left(last,1)},
      {'id':'P08','t': first || '.' || left(last,1)},
      {'id':'P09','t': first || '_' || last},
      {'id':'P10','t': first || '-' || last},
      {'id':'P11','t': last || first},
      {'id':'P12','t': last || '.' || first},
      {'id':'P13','t': last || left(first,1)},
      {'id':'P14','t': last || '.' || left(first,1)},
      {'id':'P15','t': left(first,1) || left(last,1)}
    ], x -> x.t = lp AND (NOT mononym OR x.id IN ('P01','P02'))) AS hits
  FROM dedup
)
WHERE len(hits) = 1;

-- ---- Exports (aggregate only) ----
COPY (SELECT dom, pattern, count(*) AS n FROM resolved GROUP BY dom, pattern ORDER BY dom, pattern)
  TO '/root/out/domain_pat.csv' (HEADER, DELIMITER ',');

COPY (SELECT dom, role, pattern, count(*) AS n FROM resolved GROUP BY dom, role, pattern ORDER BY dom, role)
  TO '/root/out/role_pat.csv' (HEADER, DELIMITER ',');

-- TRUE DENOMINATOR: all considered verified mailboxes (dedup), per domain and per role.
-- `dedup` = one row per (domain, localpart) for every qualifying, stoplist-passed,
-- parseable verified mailbox -- matched OR not. This is the honest denominator.
COPY (SELECT dom, count(*) AS considered_n FROM dedup GROUP BY dom)
  TO '/root/out/considered_dom.csv' (HEADER, DELIMITER ',');

COPY (SELECT dom, role_of(title, seniority) AS role, count(*) AS considered_n
      FROM dedup GROUP BY dom, role_of(title, seniority))
  TO '/root/out/considered_role.csv' (HEADER, DELIMITER ',');

COPY (SELECT
        (SELECT count(*) FROM f_verified) AS verified_rows,
        (SELECT count(*) FROM f_personal) AS after_stoplist,
        (SELECT count(*) FROM f_named)    AS after_name_parse,
        (SELECT count(*) FROM dedup)      AS rows_considered,
        (SELECT count(*) FROM resolved)   AS pairs_resolved)
  TO '/root/out/funnel.csv' (HEADER, DELIMITER ',');
