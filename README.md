## pyxss
Simple XSS vulnerability checker tool very useful with xsschecker.

## Installation
```
git clone https://github.com/rix4uni/pyxss.git
cd pyxss
python3 setup.py install
```

## pipx
Quick setup in isolated python environment using [pipx](https://pypa.github.io/pipx/)
```
pipx install --force git+https://github.com/rix4uni/pyxss.git
```

## Usage
```
usage: pyxss [-h] [-o OUTPUT_FILE] [--timeout TIMEOUT] [--popupload POPUPLOAD] [--silent] [--no-color] [--headless] [--version]

pyxss - Simple XSS vulnerability checker.

options:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Save output to a file
  --timeout TIMEOUT     Timeout in seconds for HTTP client (default 15)
  --popupload POPUPLOAD
                        Wait time for Alert popup to load in seconds (default 5)
  --silent              Run without printing the banner
  --no-color            Disable colored output
  --headless            Run in headless mode (GUI Browser)
  --version             Show current version of pyxss

Examples:
  # Step 1
  curl -s "https://raw.githubusercontent.com/rix4uni/WordList/refs/heads/main/payloads/xss/xss-small.txt" | sed 's/^/rix4uni/' | unew -q fav-xss.txt

  # Step 2
  cat urls.txt | pvreplace -silent -payload fav-xss.txt -fuzzing-part param-value -fuzzing-type replace -fuzzing-mode single | xsschecker -nc -match 'rix4uni' -vuln -t 100 | sed 's/^Vulnerable: \[[^]]*\] \[[^]]*\] //' | unew xsschecker.txt

  # Step 3
  cat xsschecker.txt | pyxss -o validxss.txt
```

## Usage Examples
```
# Step 1
curl -s "https://raw.githubusercontent.com/rix4uni/WordList/refs/heads/main/payloads/xss/xss-small.txt" | sed 's/^/rix4uni/' | unew -q fav-xss.txt

# Step 2
cat urls.txt | pvreplace -silent -payload fav-xss.txt -fuzzing-part param-value -fuzzing-type replace -fuzzing-mode single | xsschecker -nc -match 'rix4uni' -vuln -t 100 | sed 's/^Vulnerable: \[[^]]*\] \[[^]]*\] //' | unew xsschecker.txt
    
# Step 3
cat xsschecker.txt | pyxss -o validxss.txt
```
