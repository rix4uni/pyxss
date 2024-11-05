import sys
import time
import argparse
from selenium import webdriver
from selenium.webdriver.common.alert import Alert
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, WebDriverException

# Define the version
__version__ = "v0.0.2"  # Current Version of pyxss

# ANSI color codes
REDCOLOR = '\033[91m'
GREENCOLOR = '\033[92m'
CYANCOLOR = '\033[96m'
RESETCOLOR = '\033[0m'

# Colorful banner
BANNER = rf"""{CYANCOLOR}
    ____   __  __ _  __ _____ _____
   / __ \ / / / /| |/_// ___// ___/
  / /_/ // /_/ /_>  < (__  )(__  ) 
 / .___/ \__, //_/|_|/____//____/  
/_/     /____/
                        {__version__}
{RESETCOLOR}"""

def main():
    parser = argparse.ArgumentParser(
        description="pyxss - Simple XSS vulnerability checker.",
        epilog=r"""Examples:
      # Step 1
      curl -s "https://raw.githubusercontent.com/rix4uni/WordList/refs/heads/main/payloads/xss/xss-small.txt" | sed 's/^/rix4uni/' | unew -q fav-xss.txt

      # Step 2
      cat urls.txt | pvreplace -silent -payload fav-xss.txt -fuzzing-part param-value -fuzzing-type replace -fuzzing-mode single | xsschecker -nc -match 'rix4uni' -vuln -t 100 | sed 's/^Vulnerable: \[[^]]*\] \[[^]]*\] //' | unew xsschecker.txt
        
      # Step 3
      cat xsschecker.txt | pyxss -o validxss.txt
    """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('-o', '--output', type=str, metavar='OUTPUT_FILE', help='Save output to a file')
    parser.add_argument('--timeout', type=int, default=15, help='Timeout in seconds for HTTP client (default 15)')
    parser.add_argument('--popupload', type=int, default=5, help='Wait time for Alert popup to load in seconds (default 5)')
    parser.add_argument('--silent', action='store_true', help='Run without printing the banner')
    parser.add_argument('--headless', action='store_true', help='Run in headless mode (GUI Browser)')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__, help='Show current version of pyxss')
    args = parser.parse_args()

    if not args.silent:
        print(BANNER)

    # Define a function to handle WebDriver exceptions
    def handle_webdriver_exception(url, exception):
        if "ERR_CONNECTION_REFUSED" in str(exception):
            print(f"URL: {url} - Error: Connection refused (server might be down or unreachable)")
        elif "ERR_NAME_NOT_RESOLVED" in str(exception):
            print(f"URL: {url} - Error: Website not found (DNS issue)")
        elif "ERR_CONNECTION_TIMED_OUT" in str(exception):
            print(f"URL: {url} - Error: Connection timed out (website might be down)")
        elif "ERR_CONNECTION_CLOSED" in str(exception):
            print(f"URL: {url} - Error: Website might be down or receiving too many requests (429 status)")
        elif "chrome not reachable" in str(exception) or "ERR_INTERNET_DISCONNECTED" in str(exception):
            print(f"URL: {url} - Error: Internet connection is not working")
        else:
            print(f"URL: {url} - WebDriver Error: {str(exception)}")

    # Read URLs from standard input
    for url in sys.stdin:
        url = url.strip()  # Remove any whitespace or newline characters
        if not url:
            continue  # Skip empty lines

        # Check if URL starts with http:// or https://
        if not (url.startswith("http://") or url.startswith("https://")):
            print(f"Skipped invalid URL: {url}")
            continue

        try:
            # Set up Chrome options for headless mode
            options = webdriver.ChromeOptions()

            if not args.headless:
                options.add_argument('--headless')
                options.add_argument('--disable-gpu')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')

            # Initialize the WebDriver
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(args.timeout)

            # Navigate to the URL with the payload
            driver.get(url)

            try:
                # Wait for the alert to be present
                time.sleep(args.popupload)
                alert = Alert(driver)
                alert_text = alert.text

                # Save VULNERABLE output to file
                if args.output:
                    with open(args.output, "a") as file:
                        file.write(url + "\n")

                alert.accept()
                print(f"{REDCOLOR}VULNERABLE: {url} [Alert text: {alert_text}]{RESETCOLOR}")

            except NoAlertPresentException:
                print(f"{GREENCOLOR}NOT VULNERABLE: {url} [No alert found]{RESETCOLOR}")
            except TimeoutException:
                print(f"URL: {url} - Error: Page load timed out")
            except WebDriverException as e:
                handle_webdriver_exception(url, e)
            finally:
                driver.quit()

        except TimeoutException:
            print(f"URL: {url} - Error: Operation timed out (website might be down or not responding)")
        except WebDriverException as e:
            handle_webdriver_exception(url, e)
        except Exception as e:
            print(f"URL: {url} - Unexpected Error: {str(e)}")

if __name__ == "__main__":
    main()