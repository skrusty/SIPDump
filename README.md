# SIPDump

## Overview
SIPDump writes each call it sees on the interface to a pcap file, one per call, the filename matches the Call ID.

## Project Aims
* Easy separation of calls from other network traffic
* Logging of call information such as caller and callee
* Logging of call setup and takedown
* Filtering to allow you to capture only certain calls. E.g.
  * Caller or Callee
  * Destination IP or Source IP
* Conversion of RTP into WAV or other audio types

## Current Features
* Writes calls to PCAP files
* Outputs analysis file detailing call information in txt file
* Includes SIP, RTP & RTCP packets
* Allows you to select the interface to listen on

## Future Features
* Convert RTP to WAV/MP3
* Allow details to be logged to data store, e.g.
  * MSSQL
  * MYSQL
  * XML
