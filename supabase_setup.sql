-- SENSIRELAX: esquema inicial Supabase
-- Execute no SQL Editor do seu projeto Supabase.
create extension if not exists pgcrypto;

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.appointment_slots (
  id uuid primary key default gen_random_uuid(),
  slot_date date not null,
  slot_time time not null,
  status text not null default 'available' check (status in ('available','reserved','blocked')),
  created_at timestamptz not null default now(),
  unique(slot_date, slot_time)
);

create table if not exists public.appointments (
  id uuid primary key default gen_random_uuid(),
  client_name text not null check (char_length(client_name) between 2 and 100),
  client_phone text not null check (char_length(client_phone) between 8 and 25),
  notes text,
  slot_id uuid not null references public.appointment_slots(id),
  status text not null default 'pending' check (status in ('pending','confirmed','cancelled')),
  created_at timestamptz not null default now()
);

alter table public.admin_users enable row level security;
alter table public.appointment_slots enable row level security;
alter table public.appointments enable row level security;

create or replace function public.is_sensirelax_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.admin_users where user_id = auth.uid()); $$;

-- Public can read the schedule only; slot rows contain no customer details.
drop policy if exists "Public can view slots" on public.appointment_slots;
create policy "Public can view slots" on public.appointment_slots for select to anon, authenticated using (true);
drop policy if exists "Admins manage slots" on public.appointment_slots;
create policy "Admins manage slots" on public.appointment_slots for all to authenticated using (public.is_sensirelax_admin()) with check (public.is_sensirelax_admin());

drop policy if exists "Admins read appointments" on public.appointments;
create policy "Admins read appointments" on public.appointments for select to authenticated using (public.is_sensirelax_admin());
drop policy if exists "Admins update appointments" on public.appointments;
create policy "Admins update appointments" on public.appointments for update to authenticated using (public.is_sensirelax_admin()) with check (public.is_sensirelax_admin());

drop policy if exists "Admin can read own allowlist row" on public.admin_users;
create policy "Admin can read own allowlist row" on public.admin_users for select to authenticated using (user_id = auth.uid());

grant select on public.appointment_slots to anon, authenticated;
grant insert, update, delete on public.appointment_slots to authenticated;
grant select, update on public.appointments to authenticated;
grant select on public.admin_users to authenticated;

-- Booking RPC: locks the selected slot so two people cannot book it at once.
create or replace function public.book_appointment(
  p_name text, p_phone text, p_slot_id uuid, p_notes text default null
) returns uuid language plpgsql security definer set search_path = public
as $$
declare v_id uuid;
begin
  if length(trim(coalesce(p_name,''))) < 2 or length(trim(coalesce(p_phone,''))) < 8 then
    raise exception 'INVALID_DETAILS';
  end if;
  perform 1 from public.appointment_slots where id=p_slot_id and status='available' and slot_date >= current_date for update;
  if not found then raise exception 'SLOT_NOT_AVAILABLE'; end if;
  insert into public.appointments(client_name,client_phone,notes,slot_id,status)
  values(trim(p_name),trim(p_phone),nullif(trim(coalesce(p_notes,'')),''),p_slot_id,'pending') returning id into v_id;
  update public.appointment_slots set status='reserved' where id=p_slot_id;
  return v_id;
end; $$;
grant execute on function public.book_appointment(text,text,uuid,text) to anon, authenticated;

create or replace function public.admin_cancel_appointment(p_appointment_id uuid)
returns void language plpgsql security definer set search_path = public
as $$
declare v_slot uuid;
begin
  if not public.is_sensirelax_admin() then raise exception 'NOT_AUTHORIZED'; end if;
  select slot_id into v_slot from public.appointments where id=p_appointment_id and status <> 'cancelled' for update;
  if v_slot is null then raise exception 'APPOINTMENT_NOT_FOUND'; end if;
  update public.appointments set status='cancelled' where id=p_appointment_id;
  update public.appointment_slots set status='available' where id=v_slot and status='reserved';
end; $$;
grant execute on function public.admin_cancel_appointment(uuid) to authenticated;

create or replace function public.admin_reschedule_appointment(p_appointment_id uuid, p_new_slot_id uuid)
returns void language plpgsql security definer set search_path = public
as $$
declare v_old_slot uuid;
begin
  if not public.is_sensirelax_admin() then raise exception 'NOT_AUTHORIZED'; end if;
  select slot_id into v_old_slot from public.appointments where id=p_appointment_id and status <> 'cancelled' for update;
  if v_old_slot is null then raise exception 'APPOINTMENT_NOT_FOUND'; end if;
  perform 1 from public.appointment_slots where id=p_new_slot_id and status='available' and slot_date >= current_date for update;
  if not found then raise exception 'SLOT_NOT_AVAILABLE'; end if;
  update public.appointments set slot_id=p_new_slot_id, status='confirmed' where id=p_appointment_id;
  update public.appointment_slots set status='available' where id=v_old_slot and status='reserved';
  update public.appointment_slots set status='reserved' where id=p_new_slot_id;
end; $$;
grant execute on function public.admin_reschedule_appointment(uuid,uuid) to authenticated;
