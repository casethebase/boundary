-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Remove the session_connection_state table and any related triggers
  drop trigger update_connection_state_on_closed_reason on session_connection;
  drop function update_connection_state_on_closed_reason();

  drop trigger insert_session_connection_state on session_connection_state;
  drop function insert_session_connection_state();

  drop trigger update_session_state_on_termination_reason on session;
  drop function update_session_state_on_termination_reason();

  drop trigger insert_new_connection_state on session_connection;
  drop function insert_new_connection_state();

  drop trigger immutable_columns on session_connection_state;

  drop trigger wh_insert_session_connection_state on session_connection_state;
  drop function wh_insert_session_connection_state();

  drop trigger wh_insert_session_connection on session_connection;
  drop function wh_insert_session_connection();

  drop table session_connection_state;
  drop table session_connection_state_enm;

  --  If the connected_time_range is null, it means the connection is authorized but not connected.
  --  If the upper value of connected_time_range is > now() (upper range is infinity) then the state is connected.
  --  If the upper value of connected_time_range is <= now() then the connection is closed.
  alter table session_connection
    add column connected_time_range tstzrange;

  -- Insert on session_connection creates the connection entry, leaving the connected_time_range to null, indicating the connection is authorized
  -- "Connected" is handled by the function ConnectConnection, which sets the connected_time_range lower bound to now() and upper bound to infinity
  -- "Closed" is handled by the following trigger function, update_connected_time_range_on_closed_reason, which sets the connected_time_range upper bound to now()

  -- Check to see if there is a non-infinite upper bound to the time range. If so, set to now() to indicate the connection is closed
  create or replace function update_connected_time_range_on_closed_reason() returns trigger
  as $$
    begin
      if new.closed_reason is not null then
        perform from
          session_connection cs
        where
          cs.public_id = new.public_id and
          upper(cs.connected_time_range) <= now();
        if not found then
          update session_connection
          set
            connected_time_range = tstzrange(lower(connected_time_range), now())
          where
            public_id = new.public_id;
        end if;
      end if;
    return new;
    end;
  $$ language plpgsql;

  create trigger update_connected_time_range_closed_reason after update of closed_reason on session_connection
    for each row execute procedure update_connected_time_range_on_closed_reason();

  -- update_session_state_on_termination_reason() is used in an update insert trigger on the
  -- session table.  it will validate that all the session's connections are closed, and then
  -- insert a state of "terminated" in session_state for the closed session.
create or replace function update_session_state_on_termination_reason() returns trigger
  as $$
begin
    if new.termination_reason is not null then
      perform  from
        session
      where
        public_id = new.public_id and
        public_id not in (
            select session_id
              from session_connection
            where
              upper(connected_time_range) > now()
        );
      if not found then
        raise 'session %s has open connections', new.public_id;
end if;

      -- check to see if there's a terminated state already, before inserting a
      -- new one.
      perform from
        session_state ss
      where
        ss.session_id = new.public_id and
        ss.state = 'terminated';
      if found then
        return new;
end if;

insert into session_state (session_id, state)
values
    (new.public_id, 'terminated');
end if;
return new;
end;
  $$ language plpgsql;

create trigger update_session_state_on_termination_reason after update of termination_reason on session
    for each row execute procedure update_session_state_on_termination_reason();


-- wh_insert_session_connection returns an after insert trigger for the
-- session_connection table which inserts a row in
-- wh_session_connection_accumulating_fact for the new session connection.
-- wh_insert_session_connection also calls wh_rollup_connections which can
-- result in updates to wh_session_accumulating_fact.
create or replace function wh_insert_session_connection() returns trigger
  as $$
  declare
new_row wh_session_connection_accumulating_fact%rowtype;
begin
with
    authorized_timestamp (date_dim_key, time_dim_key, ts) as (
        -- TODO fix these casts
        select (select to_char(create_time, 'YYYYMMDD')::integer), (select to_char(create_time, 'SSSS')::integer), create_time
        from session_connection
        where public_id = new.public_id
          and connected_time_range is null
    ),
    session_dimension (host_dim_key, user_dim_key, credential_group_dim_key) as (
        select host_key, user_key, credential_group_key
        from wh_session_accumulating_fact
        where session_id = new.session_id
    )
insert into wh_session_connection_accumulating_fact (
        connection_id,
        session_id,
        host_key,
        user_key,
        credential_group_key,
        connection_authorized_date_key,
        connection_authorized_time_key,
        connection_authorized_time,
        client_tcp_address,
        client_tcp_port_number,
        endpoint_tcp_address,
        endpoint_tcp_port_number,
        bytes_up,
        bytes_down
    )
select new.public_id,
       new.session_id,
       session_dimension.host_dim_key,
       session_dimension.user_dim_key,
       session_dimension.credential_group_dim_key,
       authorized_timestamp.date_dim_key,
       authorized_timestamp.time_dim_key,
       authorized_timestamp.ts,
       new.client_tcp_address,
       new.client_tcp_port,
       new.endpoint_tcp_address,
       new.endpoint_tcp_port,
       new.bytes_up,
       new.bytes_down
from authorized_timestamp,
     session_dimension
         returning * into strict new_row;
return null;
end;
$$ language plpgsql;

create trigger wh_insert_session_connection after insert on session_connection
    for each row execute function wh_insert_session_connection();

  -- Replaces 15/01_wh_rename_key_columns.up.sql
  -- wh_insert_session_connection_state returns an after an update trigger on connected_time_range for the
  -- session_connection table which updates wh_session_connection_accumulating_fact.
  create function wh_insert_session_connection_state() returns trigger
  as $$
    declare
      state text;
      date_col text;
      time_col text;
      ts_col text;
      q text;
      connection_row wh_session_connection_accumulating_fact%rowtype;
    begin
      if new.connected_time_range is null then
        -- Indicates authorized connection. The update statement in this
        -- trigger will fail for the authorized state because the row for the
        -- session connection has not yet been inserted into the
        -- wh_session_connection_accumulating_fact table.
        return null;
      end if;

      if upper(new.connected_time_range) > now() then
        state = 'connected';
      else
        state = 'closed';
      end if;

      date_col = 'connection_' || state || '_date_key';
      time_col = 'connection_' || state || '_time_key';
      ts_col   = 'connection_' || state || '_time';

      q = format('update wh_session_connection_accumulating_fact
                   set (%I, %I, %I) = (select wh_date_key(%L), wh_time_key(%L), %L::timestamptz)
                   where connection_id = %L
                   returning *',
                   date_col,       time_col,       ts_col,
          -- TODO what do we think about update_time?
                   new.update_time, new.update_time, new.update_time,
                   new.public_id);
      execute q into strict connection_row;

      return null;
    end;
  $$ language plpgsql;

  create trigger wh_insert_session_connection_state after update of connected_time_range on session_connection
    for each row execute function wh_insert_session_connection_state();

commit;