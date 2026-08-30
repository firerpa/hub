# Copyright 2025 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
from .config import db
from msgpack import dumps as msgpack_dump, loads as msgpack_load

__all__ = ["reordered_queue_add_event", "enqueue_event_and_get_first_if_idle",
           "pop_next_event", "queue_pop_fallback", "queues_delete"]

REORDER_TIMEOUT = 30
DEVICE_INFLIGHT_TTL = 30
MAX_BUFFER_SIZE = 128
STATE_TTL = 600

SHA_ENQUEUE = db.script_load(b"""
local T = tonumber(ARGV[2])
local Q = KEYS[1]
local I = KEYS[2]
local D = ARGV[1]

redis.call("RPUSH", Q, D)
if redis.call("EXISTS", I) == 0 then
                local next = redis.call("LPOP", Q)
                if next then
                                redis.call("SET", I, 1, "EX", T)
                                return next
                end
end
return nil
"""
)

SHA_POP = db.script_load(b"""
local T = tonumber(ARGV[1])
local Q = KEYS[1]
local I = KEYS[2]

local next = redis.call("LPOP", Q)
if next then
                redis.call("SET", I, 1, "EX", T)
                return next
else
                redis.call("DEL", I)
                return nil
end
"""
)

SHA_REORDER = db.script_load(b"""
local device_id        = KEYS[1]
local session_key      = "ss:" .. device_id
local prev_session_key = "ps:" .. device_id
local next_key         = "ns:" .. device_id
local buffer_key       = "bf:" .. device_id
local gap_ts_key       = "gt:" .. device_id

local session_id  = ARGV[1]  -- string session id
local sequence    = tonumber(ARGV[2])
local payload     = ARGV[3]
local timeout     = tonumber(ARGV[4])
local buffer_size = tonumber(ARGV[5])
local state_ttl   = tonumber(ARGV[6])

-- special: sequence == -1 WILL message
if sequence == -1 then
                return { payload }
end

local function reset_state()
                redis.call("SET", session_key, session_id, "EX", state_ttl)
                redis.call("SET", next_key, sequence + 1, "EX", state_ttl)
                redis.call("DEL", buffer_key)
                redis.call("DEL", gap_ts_key)
                return { payload }
end

local function touch_state()
                redis.call("EXPIRE", session_key, state_ttl)
                redis.call("EXPIRE", prev_session_key, state_ttl)
                redis.call("EXPIRE", next_key, state_ttl)
                redis.call("EXPIRE", buffer_key, state_ttl)
                redis.call("EXPIRE", gap_ts_key, state_ttl)
end

local function flush_from_min()
                local keys = redis.call("HKEYS", buffer_key)
                if #keys == 0 then
                                redis.call("DEL", gap_ts_key)
                                return {}
                end
                table.sort(keys, function(a,b) return tonumber(a) < tonumber(b) end)
                local n = tonumber(keys[1])
                local out = {}
                while true do
                                local v = redis.call("HGET", buffer_key, n)
                                if not v then break end
                                out[#out + 1] = v
                                redis.call("HDEL", buffer_key, n)
                                n = n + 1
                end
                redis.call("SET", next_key, n, "EX", state_ttl)
                redis.call("DEL", gap_ts_key)
                touch_state()
                return out
end

local cur_session = redis.call("GET", session_key)
if not cur_session then
                return reset_state()
end

if session_id ~= cur_session then
                local prev_session = redis.call("GET", prev_session_key)
                if prev_session and prev_session == session_id then
                                return {}
                end
                redis.call("SET", prev_session_key, cur_session, "EX", state_ttl)
                return reset_state()
end

touch_state()

local next_seq = redis.call("GET", next_key)
if not next_seq then
                return reset_state()
end
next_seq = tonumber(next_seq)

if sequence < next_seq then
                return {}
end

if sequence == next_seq then
                local out = { payload }
                local n = next_seq + 1
                while true do
                                local v = redis.call("HGET", buffer_key, n)
                                if not v then break end
                                out[#out + 1] = v
                                redis.call("HDEL", buffer_key, n)
                                n = n + 1
                end
                redis.call("SET", next_key, n, "EX", state_ttl)
                redis.call("DEL", gap_ts_key)
                touch_state()
                return out
end

redis.call("HSET", buffer_key, sequence, payload)
local now = tonumber(redis.call("TIME")[1])
local gap_ts = redis.call("GET", gap_ts_key)
if not gap_ts then
                redis.call("SET", gap_ts_key, now, "EX", state_ttl)
                touch_state()
                return {}
end

gap_ts = tonumber(gap_ts)

if now - gap_ts >= timeout then
                return flush_from_min()
end

local buf_len = redis.call("HLEN", buffer_key)
if buf_len >= buffer_size then
                return flush_from_min()
end

touch_state()
return {}
"""
)

QUEUE_POP_FALLBACK = db.script_load(b"""
local queue1 = ARGV[1]
local queue2 = ARGV[2]

local task = redis.call("LPOP", queue1)
if not task then
                task = redis.call("LPOP", queue2)
end
return task
""")

KEYS_DELETE = db.script_load(b"""
local pattern = ARGV[1]
local cursor = "0"
local total_deleted = 0
repeat
                local res = redis.call("SCAN", cursor, "MATCH", pattern, "COUNT", 1000)
                cursor = res[1]
                local keys = res[2]
                if #keys > 0 then
                                total_deleted = total_deleted + redis.call("DEL", unpack(keys))
                end
until cursor == "0"
return total_deleted
""")


def reordered_queue_add_event(device_id, event, data):
    out = db.evalsha(   SHA_REORDER,
                        1,
                        device_id,
                        data["session_id"],
                        int(data["sequence"]),
                        msgpack_dump({"type": event, "payload": data}),
                        REORDER_TIMEOUT,
                        MAX_BUFFER_SIZE,
                        STATE_TTL,)
    return [msgpack_load(i) for i in out]


def enqueue_event_and_get_first_if_idle(device_id, data):
    return db.evalsha(  SHA_ENQUEUE,
                        2,
                        f"ev:{device_id}",
                        f"in:{device_id}",
                        msgpack_dump(data),
                        DEVICE_INFLIGHT_TTL,)


def pop_next_event(device_id):
    return db.evalsha(  SHA_POP,
                        2,
                        f"ev:{device_id}",
                        f"in:{device_id}",
                        DEVICE_INFLIGHT_TTL,)


def queue_pop_fallback(first, second):
    return db.evalsha( QUEUE_POP_FALLBACK,
                       0,
                       first,
                       second)


def queues_delete(pattern):
    return db.evalsha( KEYS_DELETE,
                       0,
                       pattern)