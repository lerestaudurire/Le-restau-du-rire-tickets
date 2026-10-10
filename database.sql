-- Le Restau du Rire — migration v2 (à exécuter dans Supabase > SQL Editor). Idempotente.
-- Chiffrement AES-256 (pgcrypto) des numéros, e-mails et codes de billets ; tout est déchiffré
-- uniquement par des fonctions réservées à l'admin / l'organisateur.
create extension if not exists pgcrypto with schema extensions;
create table if not exists public.app_secrets(k text primary key, v text not null);
alter table public.app_secrets enable row level security;
revoke all on public.app_secrets from anon, authenticated;
insert into public.app_secrets values('aes_key',encode(extensions.gen_random_bytes(32),'hex')) on conflict do nothing;
insert into public.app_secrets values('webhook_secret',encode(extensions.gen_random_bytes(24),'hex')) on conflict do nothing;

create or replace function public.enc(t text) returns bytea language sql security definer set search_path=public,extensions as
$$ select case when t is null or t='' then null else pgp_sym_encrypt(t,(select v from app_secrets where k='aes_key'),'cipher-algo=aes256,compress-algo=0') end $$;
create or replace function public.dec(b bytea) returns text language sql security definer set search_path=public,extensions as
$$ select case when b is null then null else pgp_sym_decrypt(b,(select v from app_secrets where k='aes_key')) end $$;
create or replace function public.blind(t text) returns text language sql security definer set search_path=public,extensions as
$$ select encode(hmac(regexp_replace(coalesce(t,''),'\D','','g'),(select v from app_secrets where k='aes_key'),'sha256'),'hex') $$;
revoke execute on function public.enc(text),public.dec(bytea),public.blind(text) from public,anon,authenticated;

-- Colonnes chiffrées + lien de paiement automatique
alter table public.reservations add column if not exists phone_enc bytea, add column if not exists email_enc bytea,
  add column if not exists payer_enc bytea, add column if not exists code_enc bytea, add column if not exists phone_idx text;
alter table public.orders add column if not exists phone_enc bytea, add column if not exists email_enc bytea,
  add column if not exists payer_enc bytea, add column if not exists phone_idx text;
alter table public.waitlist add column if not exists phone_enc bytea, add column if not exists phone_idx text;
alter table public.events add column if not exists pay_link text, add column if not exists ticket_info text;
alter table public.orders drop constraint if exists orders_kind_check;
drop table if exists public.promos cascade;  -- codes promo supprimés

-- Trigger : chiffre puis masque les valeurs en clair
create or replace function public.enc_row() returns trigger language plpgsql security definer set search_path=public,extensions as $$
declare j jsonb:=to_jsonb(NEW); u jsonb:='{}'; k text; c text;
begin
  if j->>'phone' is not null and j->>'phone' not like '•%' then
    if TG_TABLE_NAME='reservations' and TG_OP='INSERT' and
       (select count(*) from reservations where phone_idx=blind(j->>'phone') and created_at>now()-interval '1 hour')>=8
    then raise exception 'Trop de demandes, réessayez plus tard'; end if;
    u:=u||jsonb_build_object('phone_enc','\x'||encode(enc(j->>'phone'),'hex'),'phone_idx',blind(j->>'phone'),
         'phone','••••'||right(regexp_replace(j->>'phone','\D','','g'),2));
  end if;
  foreach k in array array['email','payer'] loop
    c:=j->>k; if c is not null and c<>'' and c not like '•%' then
      u:=u||jsonb_build_object(k||'_enc','\x'||encode(enc(c),'hex'),k,'••••'); end if; end loop;
  if j ? 'ticket_code' and j->>'ticket_code' is not null and j->>'ticket_code' not like '•%' then
    u:=u||jsonb_build_object('code_enc','\x'||encode(enc(j->>'ticket_code'),'hex'),'ticket_code','••••'); end if;
  NEW:=jsonb_populate_record(NEW,u); return NEW; end $$;
do $$ declare t text; begin foreach t in array array['reservations','orders','waitlist'] loop
  execute format('drop trigger if exists trg_enc on public.%I; create trigger trg_enc before insert or update on public.%I for each row execute function public.enc_row()',t,t);
  execute format('update public.%I set phone=phone',t); end loop; end $$;

-- Lectures déchiffrées (admin / organisateur / client avec nom + numéro)
drop function if exists public.admin_rows(); drop function if exists public.admin_waitlist(); drop function if exists public.find_ticket(text,text);
drop function if exists public.find_order(text,text); drop function if exists public.org_orders(uuid); drop function if exists public.staff_check(text);
drop function if exists public.staff_list();
create or replace function public.admin_rows() returns jsonb language plpgsql security definer set search_path=public as $$
begin if my_role()<>'admin' then raise exception 'denied'; end if;
 return coalesce((select jsonb_agg(to_jsonb(r)-'phone_enc'-'email_enc'-'payer_enc'-'code_enc'-'phone_idx'||jsonb_build_object('phone',dec(phone_enc),'email',dec(email_enc),'payer',dec(payer_enc),'ticket_code','LRR-'||upper(left(id::text,8))) order by created_at desc) from reservations r),'[]'); end $$;
create or replace function public.admin_waitlist() returns jsonb language plpgsql security definer set search_path=public as $$
begin if my_role()<>'admin' then raise exception 'denied'; end if;
 return coalesce((select jsonb_agg(to_jsonb(w)-'phone_enc'-'phone_idx'||jsonb_build_object('phone',dec(phone_enc)) order by created_at desc) from waitlist w),'[]'); end $$;
create or replace function public.find_ticket(p_phone text,p_name text) returns jsonb language sql security definer set search_path=public as $$
 select coalesce(jsonb_agg(to_jsonb(r)-'phone_enc'-'email_enc'-'payer_enc'-'code_enc'-'phone_idx'-'phone'-'email'-'payer'||jsonb_build_object('code','LRR-'||upper(left(id::text,8)))),'[]')
 from reservations r where status='confirmed' and phone_idx=blind(p_phone) and name ilike '%'||trim(p_name)||'%' $$;
create or replace function public.find_order(p_phone text,p_name text) returns jsonb language sql security definer set search_path=public as $$
 select coalesce(jsonb_agg(jsonb_build_object('id',id,'name',name,'used',used,'code','EV-'||upper(left(id::text,8)),
  'desc',(select string_agg(i->>'name'||' × '||(i->>'qty'),', ') from jsonb_array_elements(items) i))),'[]')
 from orders where status='confirmed' and phone_idx=blind(p_phone) and name ilike '%'||trim(p_name)||'%' $$;
create or replace function public.org_orders(p_event uuid) returns jsonb language plpgsql security definer set search_path=public as $$
begin if my_role()<>'admin' and not exists(select 1 from events where id=p_event and owner_id=auth.uid()) then raise exception 'denied'; end if;
 return coalesce((select jsonb_agg(to_jsonb(o)-'phone_enc'-'email_enc'-'payer_enc'-'phone_idx'||jsonb_build_object('phone',dec(phone_enc),'email',dec(email_enc),'payer',dec(payer_enc)) order by created_at desc) from orders o where event_id=p_event),'[]'); end $$;
create or replace function public.staff_check(p_code text) returns jsonb language plpgsql security definer set search_path=public as $$
declare r reservations; begin if my_role() not in('admin','staff') then raise exception 'denied'; end if;
 select * into r from reservations where id::text=lower(trim(p_code)) or 'LRR-'||upper(left(id::text,8))=upper(regexp_replace(p_code,'\s','','g')) limit 1;
 if not found then return jsonb_build_object('found',false); end if;
 return jsonb_build_object('found',true)||to_jsonb(r)-'phone_enc'-'email_enc'-'payer_enc'-'code_enc'-'phone_idx'-'phone'-'email'-'payer'; end $$;
create or replace function public.staff_list() returns jsonb language plpgsql security definer set search_path=public as $$
begin if my_role() not in('admin','staff') then raise exception 'denied'; end if;
 return coalesce((select jsonb_agg(jsonb_build_object('id',id,'code','LRR-'||upper(left(id::text,8)),'name',name,'used',used,'standard',standard,'vip',vip,'vvip',vvip,'sponsor',sponsor,'grand_sponsor',grand_sponsor)) from reservations where status='confirmed'),'[]'); end $$;

-- Pilotage plateforme (admin uniquement)
create or replace function public.admin_overview() returns jsonb language plpgsql security definer set search_path=public as $$
begin if my_role()<>'admin' then raise exception 'denied'; end if;
 return coalesce((select jsonb_agg(jsonb_build_object('title',e.title,'country',e.country,'status',e.status,
  'confirmed',coalesce(sum(o.total_qty) filter(where o.status='confirmed'),0),'pending',coalesce(sum(o.total_qty) filter(where o.status='pending'),0),
  'fc',coalesce(sum((o.amounts->>'FC')::numeric) filter(where o.status='confirmed'),0),'usd',coalesce(sum((o.amounts->>'USD')::numeric) filter(where o.status='confirmed'),0)))
  from events e left join orders o on o.event_id=e.id group by e.id),'[]'); end $$;

-- Journal d'audit des décisions admin
create table if not exists public.admin_audit(id bigserial primary key,at timestamptz default now(),who uuid,event_id uuid,old_status text,new_status text);
alter table public.admin_audit enable row level security; revoke all on public.admin_audit from anon,authenticated;
create or replace function public.audit_ev() returns trigger language plpgsql security definer set search_path=public as $$
begin if NEW.status is distinct from OLD.status then insert into admin_audit(who,event_id,old_status,new_status) values(auth.uid(),NEW.id,OLD.status,NEW.status); end if; return NEW; end $$;
drop trigger if exists trg_audit on public.events; create trigger trg_audit after update on public.events for each row execute function public.audit_ev();

-- Achat automatique : à appeler depuis le webhook de votre passerelle (Edge Function)
-- Secret : select v from app_secrets where k='webhook_secret';
create or replace function public.auto_confirm_order(p_order uuid,p_secret text) returns boolean language plpgsql security definer set search_path=public as $$
begin if p_secret is distinct from (select v from app_secrets where k='webhook_secret') then return false; end if;
 update orders set status='confirmed' where id=p_order and kind='online'; return found; end $$;

grant execute on function public.find_ticket(text,text),public.find_order(text,text),public.auto_confirm_order(uuid,text) to anon,authenticated;
grant execute on function public.admin_rows(),public.admin_waitlist(),public.org_orders(uuid),public.staff_check(text),public.staff_list(),public.admin_overview() to authenticated;
