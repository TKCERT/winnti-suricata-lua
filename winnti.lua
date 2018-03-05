--------------------------------------------------------------------------------
-- Name:   winnti.lua
-- Desc:   Surricata script for Winnti detection
-- Author: Stefan Ruester
-- Date:   2018-02-08
-- Class.: TLP:WHITE
--------------------------------------------------------------------------------

local struct = require 'struct'

function init (args)
  local needs = {}
  needs["payload"] = tostring(true)
  return needs
end


function match(args)

  -- Read flow statistics
  tscnt, tsbytes, tccnt, tcbytes = SCFlowStats()

  -- Winnti handshake must be the first part of a stream
  if tccnt ~= 1 then
    return 0
  end

  local p = args["payload"]

  if p == nil then
    return 0
  end

  -- Ignore the stream if the payload has not exactly 16 byte
  if #p ~= 16 then
    return 0
  end

  -- Extract four dwords
  local l0, l1, l2, l3 = struct.unpack("<I4I4I4I4", p:sub(1,16))

  -- False positive check -> the first 4 dwords must not be zero
  if l0 == 0 or l1 == 0 or l3 == 0 or l4 == 0 then
    return 0
  end

  -- Extract eight words
  local w0,w1,w2,w3,w4,w5,w6,w7 = struct.unpack("<I2I2I2I2I2I2I2I2", p:sub(1,16))

  -- Do the winnti XOR
  local e0 = bit.bxor(w0, bit.bxor(w4, w7))
  local e1 = bit.bxor(w1, bit.bxor(w5, w6))

  -- Check for winnti handshake
  if e0 == 0 and e1 == 0 then
    return 1
  end

  return 0
end

