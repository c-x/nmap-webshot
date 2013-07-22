---
-- @usage
-- nmap --script webshot [--script-args dirguess=no,skiperr=yes,list=filelist.log] -p 80,443 <host>
-- option skiperr 
--     if set to no, webshot 404 and others related errors.
--     if not set, or set to yes, only webshot 2xx and 3xx HTTP return codes
-- option dirguess
--     if set to no, do not try to guess directory, just webshot the '/'
--     if not set, or set to yes, try to guess directories using 'PageS' variables (see config below)
-- option list
--     if specified, try to open the submitted file for directories/files to test.
--     One dir/file per line (see sample filelist.log)
--
-- @output:
-- PORT    STATE  SERVICE
-- 80/tcp  open   http
-- | webshot: 
-- |   /opt/nmap-webshot/png/nmap-webshot-192.168.1.123_index.html
-- |   /opt/nmap-webshot/png/nmap-webshot-192.168.1.123.80_200.png
-- |   /opt/nmap-webshot/png/nmap-webshot-192.168.1.123.80_adm_200.png
-- |   /opt/nmap-webshot/png/nmap-webshot-192.168.1.123.80_admin_200.png
-- |   /opt/nmap-webshot/png/nmap-webshot-192.168.1.123.80_administrator_200.png
-- |   /opt/nmap-webshot/png/nmap-webshot-192.168.1.123.80_very.secret_200.png
-- |_  /opt/nmap-webshot/png/nmap-webshot-192.168.1.123.80_wp-upload_200.png
-- 443/tcp closed https
-- 
---

--------------------
-- CONFIG IS HERE --
--------------------
PhantomJS    = "/opt/phantomjs-1.6.0-linux-i686-dynamic/bin/phantomjs --ignore-ssl-errors=yes"
ScreenshotJS = "/opt/nmap-webshot/screenshot.js"
PNGDir       = "/opt/nmap-webshot/png"
PageS        = { '/adm', '/admin', '/administrator', '/robots.txt' , '/wp-upload' }

------------------------------------------------------------------------
-- DO NOT EDIT ANYTHING BELOW THIS LINE OR THE EARTH WILL COLLAPSE oO --
------------------------------------------------------------------------

description = [[
Take screenshot of web pages of discovered web services and do some little directory guessing.
]]

author     = "@_CLX"
license    = "GPLv2"
categories = {"discovery", "safe"}

local shortport = require 'shortport'
local http = require 'http'
local io = require 'io'
local stdnse = require 'stdnse'

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")


action = function(host, port)

	-- use external list ?
	if nmap.registry.args.list ~= nil then
		
		local f = assert(io.open(nmap.registry.args.list, 'r'), "Failed to open submitted input list")

		PageS = {}
		for l in f:lines() do
			table.insert(PageS, l)
		end
		f:close()
	end

	local prefix = "http://"
	if port.number == 443 then
		prefix = "https://"
	end

	local html     = ""
	local htmlFile = "nmap-webshot-" .. host.ip .. "_index.html"
	local msg   = ""

	-- Just get the / page ?
	local loops = #PageS
	if nmap.registry.args.dirguess == "no" then
		loops = 0
	end


	for i = 0, loops do

		local page
		if i == 0 then
			page  = '/'
		else
			page  = PageS[i]
		end

		local r = http.get(host.ip, port.number, page)

		-- check the http code before asking a screeshot
		-- WebShot for pages with 1xx, 4xx, 5xx return codes ?
		if ( nmap.registry.args.skiperr == "no" or (r.status >= 200 and r.status < 400) ) then
			
			-- url to retrieve (should be improve for vhosts by using DNS names)
			local url = prefix .. host.ip .. ":" .. port.number .. page

			-- destination filename 
			local f_dst = "nmap-webshot-" .. host.ip .. "." .. port.number .. "_" .. page .. "_" .. r.status .. ".png"
	
			-- replace '/' in filename by dots.
			f_dst = string.gsub(f_dst, "_/", "_")	
			f_dst = string.gsub(f_dst, "/", ".")

			-- execute command, take the screenshot using PhamtomJS
			local cmd = PhantomJS .. " " .. ScreenshotJS .. " " .. url .. " " .. PNGDir .. '/' .. f_dst  .. " 2>/dev/null 1>/dev/null"
			local ret = os.execute(cmd)

			if ret == true then
				msg =  msg .. f_dst .. "\n"
				html = html .. url .. "<br><div align='center'><img src='./" .. f_dst .."' /></div><br>\n"
			else
				msg = msg .. "Error while tacking the picture. Smile please...\n"
			end
		end
	end
	
	if html ~= "" then
		msg =  htmlFile .. "\n" .. msg
		htmlFile = PNGDir .. "/" .. htmlFile

		local f = assert(io.open(htmlFile, 'w'), "Failed to open output html file for writing")
		f:write("<html><body>\n")
		f:write(html)
		f:write("</body></html>\n")
		f:close()
	end

	return stdnse.format_output(true, msg)
end

