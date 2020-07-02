#
# Author: Jeff Atkinson (jeff.atkinson@verizonmedia.com)
#
# Copyright 2020, Verizon Media
# Licensed under the terms of the Apache 2.0 license. See LICENSE file in github.com/yahoo/Spicy_WireGuard root directory for terms

# Dynamic protocol Signature for Wireguard to attach to stream.

signature dpd_wg_initiation {
  ip-proto = udp
  payload /^\x01\x00\x00\x00/
  enable "spicy_WireGuard"
  event "WireGuard Handshake Initiation"
}
