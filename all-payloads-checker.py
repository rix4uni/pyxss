from selenium import webdriver
from selenium.webdriver.common.alert import Alert
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, WebDriverException
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import argparse
import subprocess
import os
import re

def is_notify_installed():
    # Full path to the notify command
    notify_path = '/root/go/bin/notify'

    # Check if the file exists and is executable
    return os.path.isfile(notify_path) and os.access(notify_path, os.X_OK)

def is_valid_url(url):
    # Simple URL validation (checks if the URL starts with http:// or https://)
    return re.match(r'^https?://', url) is not None

def process_url(url, notify_discord, output):
    if not is_valid_url(url):
        print(f"\033[1;33mSkipped invalid URL: {url}\033[0;0m")
        return

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
        driver.set_page_load_timeout(15)

        # Navigate to the URL with the payload
        driver.get(url)

        try:
            # Wait for the alert to be present
            alert = Alert(driver)
            alert_text = alert.text
            print(f"\033[1;31mVULNERABLE: {url} [Alert text: {alert_text}]\033[0;0m")

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
                with open(output, "a") as file:
                    file.write(url + "\n")

            time.sleep(5)
            # Dismiss the alert
            alert.dismiss()
        except NoAlertPresentException:
            print(f"\033[1;35mNOT VULNERABLE: {url} [No alert found]\033[0;0m")
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
        print(f"URL: {url} - Unexpected Error: {str(e)}")


def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description='XSS Vulnerability Validator')
    parser.add_argument('-o', '--output', type=str, metavar='OUTPUT_FILE', help='Save output to a file')
    parser.add_argument('--discord', action='store_true', help='Send notifications to Discord')
    args = parser.parse_args()

    try:
        # Read URLs from the file
        with open('urls.txt', 'r', errors="replace") as file:
            urls = [line.strip() for line in file]

        # Process URLs in batches of 10
        batch_size = 10
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            futures = [executor.submit(process_url, url, args.discord, args.output) for url in urls]

            # Wait for all futures to complete
            for future in as_completed(futures):
                try:
                    future.result()  # Raise exception if there was an error
                except Exception as e:
                    print(f"Error processing URL: {str(e)}")
    except KeyboardInterrupt:
        print("Execution interrupted by user. Cleaning up...")
        exit(0)
    finally:
        executor.shutdown(wait=False)  # Attempt to shut down the executor immediately
        print("Exiting program.")

if __name__ == "__main__":
    main()
