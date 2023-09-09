--[[
File name : malicious_uri.lua
Author    : samiux (https://samiux.github.io)
Date      : MAR 25, 2023
Version   : 0.1
Remark    : cannot detect https traffic
Rule      : drop http any any -> any any (msg:"Malicious URI"; flow:stateless; lua:malicious_uri.lua; priority:1; classtype:policy-violation; sid:1010032; rev:1;)
]]

function init (args)
    local needs = {}
    needs["http.header"] = tostring(true)
    needs["http.uri.raw"] = tostring(true)
    return needs
end

function match(args)
    --Read from file and put into an arrary
    local file = io.open("\/var\/lib\/suricata\/rules\/malicious.uri", "rb")
    lines = {}

    for line in file:lines() do
        table.insert(lines, line)
    end

    file:close()

    --local file = io.open("\/var\/log\/suricata\/malicious_uri.log", "a+")
    header = tostring(args["http.header"])
    uri = tostring(args["http.uri.raw"])    
    a = header .. uri:sub(2)
    if #a > 0 then
        for _, v in ipairs(lines) do
            --file:write("Log : " .. a .. " -- " .. v .. "\n")
            if string.find(v, a) then
                --file:write("Match : " .. a .. " -- " .. v .. "\n")
                --file:flush()
                --file:close()
                return 1
            end
        end
    end
    --file:flush()
    --file:close()
    return 0
end

