local path = ngx.var.id
local http = require "resty.http"
local requ = http.new()

-- check authorization from local service
local ok, err = requ:connect("127.0.0.1", 8800)
if not ok then
        ngx.exit(500)
end

local res, err = requ:request({
method = "HEAD",
path = "/validate/" .. path,
headers = {
        ["Cookie"] = ngx.var.http_cookie,
        ["Host"] = "lamda.local"
},
})
local uid = res.headers["X-ClientId"]
requ:close()
if not (res and res.status == 200) then
        ngx.exit(404)
end

local redis = require "resty.redis"
local client = redis:new()

client:set_timeout(500)

local password = os.getenv("REDIS_PASSWORD")
if not password then
        ngx.exit(500)
end
local ok, err = client:connect("redis-slave02", 6379)
if not ok then
        ngx.exit(503)
end
local ok, err = client:auth(password)
if not ok then
        ngx.exit(503)
end

-- append name to domain
local gw, err = client:get("gw:" .. path)
if err then
        ngx.exit(500)
end
if gw == ngx.null then
        ngx.exit(404)
end

local loc, tok = gw:match("([^,]+),([^,]+)")

ngx.var.target_tok = tok
ngx.var.target_loc = loc
ngx.var.target_uid = uid

local raw_uri = ngx.var.request_uri
local stripped = ngx.re.sub(raw_uri, "^/d/[0-9a-z]+", "")
ngx.var.target_uri = ngx.re.sub(stripped, "\\?.*$", "")

ngx.var.target_url = "https://" .. loc

client:close()
