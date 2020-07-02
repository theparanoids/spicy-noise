# This Zeek scritp will log out details of WireGuard sessions.
#
# Author: Jeff Atkinson (jeff.atkinson@verizonmedia.com)
#
# Copyright 2020, Verizon Media
# Licensed under the terms of the Apache 2.0 license. See LICENSE file in github.com/yahoo/Spicy_WireGuard root directory for terms

module WireGuard;

export {

    redef enum Log::ID += {WGLOG};

    type Info: record {
      ts: time	&log;
      id: conn_id	&log;
      msg_type:		string &log &optional;
      sender:		string &log &optional;
      receiver:		string &log &optional;
      unenc_ephemeral:	string &log &optional;
      enc_static:	string &log &optional;
      enc_timestamp:	string &log &optional;
      enc_nothing:	string &log &optional;
      nonce:		string &log &optional;
      enc_cookie:	string &log &optional;
      mac1:		string &log &optional;
      mac2:		string &log &optional;
      enc_payload_len:	int &log &optional;
      enc_payload:	string &log &optional;
    };

}

event zeek_init() {

  Log::create_stream(WireGuard::WGLOG, [$columns=Info, $path="wireguard"] );

}

event WireGuard::initiation(c: connection, sender_index: int, unenc_ephemeral: string, enc_static: string, enc_timestamp: string, mac1: string, mac2: string )
{
  #print "";
  #print "ZEEK - Initiation";

  local rec: WireGuard::Info = [ $ts = network_time(), $id = c$id ];
  add c$service["WireGuard"];
  rec$sender = fmt("%x",sender_index);
  rec$unenc_ephemeral = bytestring_to_hexstr(unenc_ephemeral);
  rec$enc_static = bytestring_to_hexstr(enc_static);
  rec$enc_timestamp = bytestring_to_hexstr(enc_timestamp);
  rec$mac1 = bytestring_to_hexstr(mac1);
  rec$mac2 = bytestring_to_hexstr(mac2);
  rec$msg_type = "INITIATION";
  Log::write(WireGuard::WGLOG, rec);
}

event WireGuard::response(c: connection, sender_index: int, receiver_index: int, unenc_ephemeral: string, enc_nothing: string, mac1: string, mac2: string)
{ 
  #print "";
  #print "ZEEK - RESPONSE"; 

  local rec: WireGuard::Info = [ $ts = network_time(), $id = c$id ];
  rec$msg_type = "RESPONSE";
  rec$sender = fmt("%x", sender_index);
  rec$receiver = fmt("%x",receiver_index);
  rec$unenc_ephemeral = bytestring_to_hexstr(unenc_ephemeral);
  rec$enc_nothing = bytestring_to_hexstr(enc_nothing);
  rec$mac1 = bytestring_to_hexstr(mac1);
  rec$mac2 = bytestring_to_hexstr(mac2);
  Log::write(WireGuard::WGLOG, rec);
}

event WireGuard::cookie(c: connection, receiver_index: int, nonce: vector of int , encrypted_cookie: vector of int )
{ 
  print "COOKIE"; 
}

event WireGuard::transport(c: connection, receiver_index: int, num_pkts: int, enc_packet: string )
{ 
  #print "";
  #print "ZEEK - TRANSPORT";

  local rec: WireGuard::Info = [ $ts = network_time(), $id = c$id ];
  rec$msg_type = "TRANSPORT";
  rec$receiver = fmt("%x",receiver_index);
  rec$enc_payload_len = |enc_packet|;
  rec$enc_payload = enc_packet;
  Log::write(WireGuard::WGLOG, rec);
}
