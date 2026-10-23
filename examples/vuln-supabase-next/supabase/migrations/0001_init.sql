-- Deliberately vulnerable fixture. RLS is enabled on one table and forgotten on three.
create table if not exists profiles (
  id uuid primary key references auth.users,
  email text,
  full_name text
);
alter table profiles enable row level security;

create table orders (
  id bigserial primary key,
  user_id uuid references auth.users,
  total_cents int,
  card_last4 text
);

create table support_tickets (
  id bigserial primary key,
  user_id uuid,
  body text
);

create table api_keys (
  id bigserial primary key,
  user_id uuid,
  secret text
);
