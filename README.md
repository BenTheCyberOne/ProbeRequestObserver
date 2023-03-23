# ProbeRequestObserver
C Program for observing and logging probe requests. Logs all sniffed requests to a sqlite3 database for future processing. Lightweight and (mostly) portable. Still in development, expect more features and a better user experience with each new release!

 # Requirements
 PRO currently requires the following to work correctly:
 

 - A compatible wireless interface set to monitor mode
 - SQLite3 library
 - LibPCAP library

# Building
Currently, PRO can be compiled by simply running:

    gcc PRO.c -o PRO -lpcap -lsqlite3

# Usage

    sudo ./PRO <device in monitor mode> [--new-db]
   PRO requires sudo privileges in order to set the selected device's channel every few seconds. This ensures PRO sniffs the common 2.4GHz channels for any possible probe requests.
   The optional --new-db argument drops the requests table in the SQLite3 db file, allowing you to start fresh!
