-- ITzMeow80 — snippet di esempio in Lua
-- Utilità per risorse FiveM: validazione eventi e logging sicuro.

local M = {}

--- Whitelist dei nomi evento che i client possono invocare.
local ALLOWED_EVENTS = {
    ["myrp:notify"] = true,
    ["myrp:syncCoords"] = true,
    ["myrp:requestVehicle"] = true,
}

--- Limiti anti-spam per giocatore (source -> ultimo timestamp).
local lastTrigger = {}

local RATE_LIMIT_MS = 250

--- Controlla che un evento rispetti whitelist e rate limit.
-- @param source number id del giocatore
-- @param eventName string nome evento
-- @return boolean, string|nil
function M.canTrigger(source, eventName)
    if type(eventName) ~= "string" or not ALLOWED_EVENTS[eventName] then
        M.log(2, ("Evento non consentito: %s (source %s)"):format(tostring(eventName), tostring(source)))
        return false, "evento_non_permesso"
    end

    local now = GetGameTimer()
    local last = lastTrigger[source]
    if last and (now - last) < RATE_LIMIT_MS then
        M.log(2, ("Rate limit: source %s su %s"):format(tostring(source), eventName))
        return false, "rate_limited"
    end

    lastTrigger[source] = now
    return true
end

--- Sanitizza una stringa in ingresso (rimuove controllo e tag HTML).
-- @param value string
-- @return string
function M.sanitize(value)
    if type(value) ~= "string" then
        return ""
    end
    value = value:gsub("[%c]", "")
    value = value:gsub("[<>]", "")
    if #value > 256 then
        value = value:sub(1, 256)
    end
    return value
end

--- Log strutturato con livello (0=info, 1=warn, 2=error).
function M.log(level, message)
    local names = { [0] = "INFO", [1] = "WARN", [2] = "ERROR" }
    print(("[ItzMeow80] [%s] %s"):format(names[level] or "INFO", message))
end

--- Pulizia periodica delle entry del rate limit.
function M.cleanup()
    local now = GetGameTimer()
    for src, last in pairs(lastTrigger) do
        if now - last > 60000 then
            lastTrigger[src] = nil
        end
    end
end

-- Esempio di handler:
-- AddEventHandler("myrp:eventName", function(_, _, eventName)
--     local ok, err = M.canTrigger(source, eventName)
--     if not ok then return end
--     ...
-- end)

return M
