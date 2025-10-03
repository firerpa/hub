local http = require "resty.http"
local requ = http.new()

-- check authorization from local service
local ok, err = requ:connect("unix:/run/server.sock")
if not ok then
        ngx.exit(500)
end

local res, err = requ:request({
method = "HEAD",
path = "/validate/novnc",
headers = {
        ["Cookie"] = ngx.var.http_cookie,
        ["Host"] = "cloud.local"
},
})
requ:close()
if not (res and res.status == 200) then
        ngx.exit(404)
end