from selenium import webdriver
from selenium.webdriver.common.alert import Alert
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, WebDriverException
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import argparse
import subprocess
import os
import re
import threading
import sys

# Define the version
__version__ = "v0.0.1"  # Current Version of pyxss

# ANSI color codes
REDCOLOR = '\033[91m'
GREENCOLOR = '\033[92m'
PURPLECOLOR = '\033[0;35m'
CYANCOLOR = '\033[96m'
RESETCOLOR = '\033[0m'

# Colorful banner
BANNER = rf"""{CYANCOLOR}
 ____  _  _  _  _  ___  ___ 
(  _ \( \/ )( \/ )/ __)/ __)
 )___/ \  /  )  ( \__ \\__ \
(__)   (__) (_/\_)(___/(___/
                        {__version__}
{RESETCOLOR}"""

print(BANNER)

# Lock for synchronizing access to the vulnerable_flags dictionary
lock = threading.Lock()

def is_notify_installed():
    # Full path to the notify command
    notify_path = '/root/go/bin/notify'

    # Check if the file exists and is executable
    return os.path.isfile(notify_path) and os.access(notify_path, os.X_OK)

def is_valid_url(url):
     # Simple URL validation (checks if the URL starts with http:// or https://)
    return re.match(r'^https?://', url) is not None

def extract_base_url(url):
    # Extract the base URL before any parameters
    return re.split(r'[?&]', url)[0]

def process_url(url, vulnerable_flags, notify_discord, output, append, timeout):
    base_url = extract_base_url(url)

    if not is_valid_url(url):
        print(f"\033[1;33mSkipped invalid URL: {url}\033[0;0m")
        return False

    with lock:
        if vulnerable_flags.get(base_url, False):
            # print(f"\033[1;33mSkipping URL as base URL {base_url} is already flagged as vulnerable.\033[0;0m")
            return False

    try:
        # Set up Chrome options for headless mode
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')  # Optional: for compatibility
        options.add_argument('--no-sandbox')   # Optional: for running in a container
        options.add_argument('--disable-dev-shm-usage')  # Optional: to avoid out of memory issues

        # Set up the WebDriver with headless mode
        driver = webdriver.Chrome(options=options)

        # Set a timeout for page load
        driver.set_page_load_timeout(timeout)

        # Navigate to the URL with the payload
        driver.get(url)

        try:
            # Wait for the alert to be present
            alert = Alert(driver)
            alert_text = alert.text

            with lock:
                if not vulnerable_flags.get(base_url, False):
                    print(f"{REDCOLOR}VULNERABLE: {url} [Alert text: {alert_text}]{RESETCOLOR}")

                    # Send to Discord
                    if notify_discord:
                        if is_notify_installed():
                            notify_command = ['notify', '-silent', '-duc', '-bulk', '-id', 'xssvalidator']
                            result = subprocess.run(notify_command, input=url, text=True, capture_output=True)
                            # Strip trailing newlines from result.stdout
                            output_message = result.stdout.strip()
                            print(f"\033[1;36mMessage sent to Discord successfully!: {output_message}\033[0;0m")
                        else:
                            print("Unable to sent Discord Message notify is not installed, RUN: go install -v github.com/projectdiscovery/notify/cmd/notify@latest")
                    
                    # Save VULNERABLE output to file
                    if output:
                        with open(output, "w") as file:
                            file.write(url + "\n")
                    if append:
                        with open(append, "a") as file:
                            file.write(url + "\n")
                       
                    vulnerable_flags[base_url] = True

                    # Sleep for 5 seconds
                    time.sleep(5)

                    # Dismiss the alert
                    alert.dismiss()
                    return True  # Alert found
            return False  # This will not be reached if an alert was found and processed

        except NoAlertPresentException:
            return False  # No alert found
            # print(f"\033[1;35mNOT VULNERABLE: {url} [No alert found]\033[0;0m")
        except TimeoutException:
            print(f"URL: {url} - Error: Page load timed out")
        except WebDriverException as e:
            if "ERR_CONNECTION_REFUSED" in str(e):
                print(f"URL: {url} - Error: Connection refused (server might be down or unreachable)")
            elif "ERR_NAME_NOT_RESOLVED" in str(e):
                print(f"URL: {url} - Error: Website not found (DNS issue)")
            elif "ERR_CONNECTION_TIMED_OUT" in str(e):
                print(f"URL: {url} - Error: Connection timed out (website might be down)")
            elif "chrome not reachable" in str(e) or "ERR_INTERNET_DISCONNECTED" in str(e):
                print(f"URL: {url} - Error: Internet connection is not working")
            else:
                print(f"URL: {url} - WebDriver Error: {str(e)}")
        finally:
            # Close the browser
            driver.quit()

    except TimeoutException:
        print(f"URL: {url} - Error: Operation timed out (website might be down or not responding)")
    except WebDriverException as e:
        if "ERR_CONNECTION_REFUSED" in str(e):
            print(f"URL: {url} - Error: Connection refused (server might be down or unreachable)")
        elif "ERR_NAME_NOT_RESOLVED" in str(e):
            print(f"URL: {url} - Error: Website not found (DNS issue)")
        elif "ERR_CONNECTION_TIMED_OUT" in str(e):
            print(f"URL: {url} - Error: Connection timed out (website might be down)")
        elif "chrome not reachable" in str(e) or "ERR_INTERNET_DISCONNECTED" in str(e):
            print(f"URL: {url} - Error: Internet connection is not working")
        else:
            print(f"URL: {url} - WebDriver Error: {str(e)}")
    except Exception as e:
        return False
        # print(f"URL: {url} - Unexpected Error: {str(e)}")


def generate_payload_urls(base_url, args):
    try:
        command = f"echo {base_url} | python3 tools/pvreplace.py -payload {args.payload} -part param-value -type replace -mode single -without-encode | go run tools/xsschecker.go -match 'rix4uni' -t 100 -integrate"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if args.verbose:
            # Split the output into lines and count them
            output_lines = result.stdout.splitlines()
            line_count = len(output_lines)

            # Print the number of lines and output
            print(f"INFO: pvreplace and xsschecker Found URLs: {line_count}\n{result.stdout.strip()}")
        else:
            line_count = len(result.stdout.splitlines())
            print(f"INFO: pvreplace and xsschecker Found URLs: {line_count}")

        return result.stdout.strip().splitlines()
    except Exception as e:
        print(f"Error generating payload URLs for {base_url}: {str(e)}")
        return []

def main():
    # Argument parsing with examples in the epilog
    parser = argparse.ArgumentParser(
        description='pyxss is a XSS Vulnerability Validator',
        epilog='Examples:\n'
               '  python3 pyxss.py -list httpx.txt -payload payloads/xsspayloads.txt\n'
               '  python3 pyxss.py -list httpx.txt -payload payloads/xsspayloads.txt -o validxss.txt\n'
               '  python3 pyxss.py -list httpx.txt -payload payloads/xsspayloads.txt -o validxss.txt -discord\n'
               '  python3 pyxss.py -list httpx.txt -payload payloads/xsspayloads.txt -o validxss.txt -discord -v\n',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-o', '--output', type=str, metavar='OUTPUT_FILE', help='Save output to a file')
    parser.add_argument('-a', '--append', type=str, metavar='OUTPUT_FILE', help='Append output to a file')
    parser.add_argument('-discord', action='store_true', help='Send notifications to Discord')
    parser.add_argument('--timeout', default=15, help='Timeout (in seconds) for http client (default 15)')
    parser.add_argument('-list', nargs='?', default=None, help='File to read Httpx alive URLs')
    parser.add_argument('-payload', nargs='?', default=None, help='Payload file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Display info of what is going on')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__, help='Show Current Version of pyxss')
    args = parser.parse_args()

     # Check if both -list and -payload are not provided
    if args.list is None or args.payload is None:
        print("Error: You must provide both -list and -payload arguments.")
        sys.exit(1)

    # Check if the specified files exist
    if args.list and not os.path.isfile(args.list):
        print(f"Error: The file '{args.list}' does not exist.")
        sys.exit(1)

    if args.payload and not os.path.isfile(args.payload):
        print(f"Error: The file '{args.payload}' does not exist.")
        sys.exit(1)

    vulnerable_flags = {}  # Shared dictionary to track vulnerable base URLs

    try:
        with open(args.list, 'r', errors="replace") as file:
            base_urls = [line.strip() for line in file]

        for base_url in base_urls:
            stripped_base_url = extract_base_url(base_url)
            
            if vulnerable_flags.get(stripped_base_url, False):
                print(f"\033[1;33mSkipping already flagged vulnerable base URL: {stripped_base_url}\033[0;0m")
                continue

            print(f"Processing URL: {base_url}")
            payload_urls = generate_payload_urls(base_url, args)

            # Process URLs 10 urls at a time
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(process_url, url, vulnerable_flags, args.discord, args.output, args.append, args.timeout) for url in payload_urls]

                # Wait for all futures to complete
                for future in as_completed(futures):
                    try:
                        if future.result():  # Raise exception if there was an error
                            print(f"\033[1;33mAlert found! Skipping remaining URLs for base URL: {stripped_base_url}\033[0;0m")
                            break  # Skip remaining URLs if alert is found
                    except Exception as e:
                        print(f"Error processing URL: {str(e)}")

    except KeyboardInterrupt:
        print("Execution interrupted by user. Cleaning up...")
        exit(0)
    finally:
        print("INFO: Succesfully Scanned all URLs!.")

if __name__ == "__main__":
    main()
