# pyxss

# Usage
```
pyxss.py -h

 ____  _  _  _  _  ___  ___
(  _ \( \/ )( \/ )/ __)/ __)
 )___/ \  /  )  ( \__ \\__ \
(__)   (__) (_/\_)(___/(___/
                        v0.0.1

usage: pyxss.py [-h] [-o OUTPUT_FILE] [-a OUTPUT_FILE] [-discord] [--timeout TIMEOUT] [-list [LIST]] [-payload [PAYLOAD]] [-v] [--version]

pyxss is a XSS Vulnerability Validator

options:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Save output to a file
  -a OUTPUT_FILE, --append OUTPUT_FILE
                        Append output to a file
  -discord              Send notifications to Discord
  --timeout TIMEOUT     Timeout (in seconds) for http client (default 15)
  -list [LIST]          File to read Httpx alive URLs
  -payload [PAYLOAD]    Payload file
  -v, --verbose         Display info of what is going on
  --version             Show Current Version of pyxss

Examples:
  python3 pyxss.py -list httpx.txt -payload payloads/xsspayloads.txt
  python3 pyxss.py -list httpx.txt -payload payloads/xsspayloads.txt -o validxss.txt
  python3 pyxss.py -list httpx.txt -payload payloads/xsspayloads.txt -o validxss.txt -discord
  python3 pyxss.py -list httpx.txt -payload payloads/xsspayloads.txt -o validxss.txt -discord -v
```
