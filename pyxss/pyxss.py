import sys
import argparse
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, WebDriverException

# Define the version
__version__ = "v0.0.4"  # Current Version of pyxss

# ANSI color codes
REDCOLOR = '\033[91m'
GREENCOLOR = '\033[92m'
CYANCOLOR = '\033[96m'
RESETCOLOR = '\033[0m'

# Global driver tracking for signal handler
active_drivers = set()
drivers_lock = threading.Lock()

# Shutdown flag for graceful interruption
shutdown_requested = threading.Event()

# Colorful banner
BANNER = rf"""{CYANCOLOR}
    ____   __  __ _  __ _____ _____
   / __ \ / / / /| |/_// ___// ___/
  / /_/ // /_/ /_>  < (__  )(__  ) 
 / .___/ \__, //_/|_|/____//____/  
/_/     /____/
                        {__version__}
{RESETCOLOR}"""


def create_chrome_options(args):
    """Create and configure Chrome options for optimal memory usage."""
    options = webdriver.ChromeOptions()
    
    # Fix headless flag logic - enable headless when flag is set
    if args.headless:
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
    
    # Memory-efficient options
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-plugins')
    options.add_argument('--disable-extensions')
    options.add_argument('--disable-background-networking')
    options.add_argument('--disable-background-timer-throttling')
    options.add_argument('--disable-renderer-backgrounding')
    options.add_argument('--disable-backgrounding-occluded-windows')
    options.add_argument('--disable-ipc-flooding-protection')
    # Note: We cannot disable JavaScript as XSS detection requires it
    # Note: We cannot disable images as it might affect XSS payload rendering
    options.add_argument('--memory-pressure-off')
    options.add_argument('--disable-features=TranslateUI,BlinkGenPropertyTrees')
    options.add_argument('--disable-logging')
    options.add_argument('--disable-permissions-api')
    
    # Performance options
    options.add_argument('--disable-software-rasterizer')
    options.add_argument('--disable-web-security')  # May be needed for XSS testing
    
    # SSL certificate bypass options
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--test-type')
    
    return options


def signal_handler(signum, frame):
    """Handle SIGINT (CTRL+C) to close all Chrome windows."""
    shutdown_requested.set()
    raise KeyboardInterrupt


def handle_webdriver_exception(url, exception):
    """Handle WebDriver exceptions with user-friendly messages."""
    error_str = str(exception)
    if "ERR_CONNECTION_REFUSED" in error_str:
        return f"URL: {url} - Error: Connection refused (server might be down or unreachable)"
    elif "ERR_NAME_NOT_RESOLVED" in error_str:
        return f"URL: {url} - Error: Website not found (DNS issue)"
    elif "ERR_CONNECTION_TIMED_OUT" in error_str:
        return f"URL: {url} - Error: Connection timed out (website might be down)"
    elif "ERR_CONNECTION_CLOSED" in error_str:
        return f"URL: {url} - Error: Website might be down or receiving too many requests (429 status)"
    elif "chrome not reachable" in error_str or "ERR_INTERNET_DISCONNECTED" in error_str:
        return f"URL: {url} - Error: Internet connection is not working"
    else:
        return f"URL: {url} - WebDriver Error: {error_str}"


def process_url(url, args, file_lock, output_file, stats):
    """Process a single URL for XSS vulnerability."""
    url = url.strip()
    
    # Skip empty lines
    if not url:
        return None, None
    
    # Validate URL format
    if not (url.startswith("http://") or url.startswith("https://")):
        return None, f"Skipped invalid URL: {url}"
    
    driver = None
    try:
        # Check if shutdown was requested
        if shutdown_requested.is_set():
            return None, None
        
        # Create Chrome options
        options = create_chrome_options(args)
        
        # Initialize the WebDriver
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(args.timeout)
        
        # Add driver to tracking set for signal handler
        with drivers_lock:
            active_drivers.add(driver)
        
        # Check if shutdown was requested after creating driver
        if shutdown_requested.is_set():
            return None, None
        
        # Navigate to the URL with the payload
        driver.get(url)
        
        try:
            # Wait for alert using WebDriverWait instead of fixed sleep
            wait = WebDriverWait(driver, args.popupload)
            alert = wait.until(EC.alert_is_present())
            alert_text = alert.text
            alert.accept()
            
            result_msg = f"VULNERABLE: {url} [Alert text: {alert_text}]"
            result_type = "vulnerable"
            
        except TimeoutException:
            # No alert found - not vulnerable
            result_msg = f"NOT VULNERABLE: {url} [No alert found]"
            result_type = "not_vulnerable"
            
        except NoAlertPresentException:
            # No alert present
            result_msg = f"NOT VULNERABLE: {url} [No alert found]"
            result_type = "not_vulnerable"
            
        except WebDriverException as e:
            error_msg = handle_webdriver_exception(url, e)
            return None, error_msg
            
        # Thread-safe file writing
        if output_file:
            with file_lock:
                if args.no_color:
                    output_file.write(f"{result_msg}\n")
                else:
                    if result_type == "vulnerable":
                        output_file.write(f"{REDCOLOR}{result_msg}{RESETCOLOR}\n")
                    else:
                        output_file.write(f"{GREENCOLOR}{result_msg}{RESETCOLOR}\n")
                output_file.flush()
        
        # Update stats
        with stats['lock']:
            stats['processed'] += 1
            if result_type == "vulnerable":
                stats['vulnerable'] += 1
            else:
                stats['not_vulnerable'] += 1
        
        # Return result for printing
        return result_type, result_msg
        
    except TimeoutException:
        error_msg = f"URL: {url} - Error: Page load timed out"
        with stats['lock']:
            stats['processed'] += 1
        return None, error_msg
        
    except WebDriverException as e:
        error_msg = handle_webdriver_exception(url, e)
        with stats['lock']:
            stats['processed'] += 1
        return None, error_msg
        
    except Exception as e:
        error_msg = f"URL: {url} - Unexpected Error: {str(e)}"
        with stats['lock']:
            stats['processed'] += 1
        return None, error_msg
        
    finally:
        # Ensure WebDriver is properly cleaned up (optimized for speed)
        if driver:
            # Remove driver from tracking set
            with drivers_lock:
                active_drivers.discard(driver)
            try:
                # Use close() instead of quit() for faster cleanup
                # quit() closes all windows and is slower
                driver.close()
            except Exception:
                pass
            try:
                # Stop service with timeout protection
                if hasattr(driver, 'service') and driver.service:
                    driver.service.stop()
            except Exception:
                pass


def print_result(result_type, result_msg, error_msg, args):
    """Print result to stdout with proper formatting."""
    if error_msg:
        print(error_msg, flush=True)
    elif result_msg:
        if args.no_color:
            print(result_msg, flush=True)
        else:
            if result_type == "vulnerable":
                print(f"{REDCOLOR}{result_msg}{RESETCOLOR}", flush=True)
            else:
                print(f"{GREENCOLOR}{result_msg}{RESETCOLOR}", flush=True)


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
    parser.add_argument('--timeout', type=int, default=15, help='Timeout in seconds for page load (default 15)')
    parser.add_argument('--popupload', type=int, default=5, help='Wait time for Alert popup to load in seconds (default 5)')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Number of parallel workers for URL scanning (default 4)')
    parser.add_argument('--silent', action='store_true', help='Run without printing the banner')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--headless', action='store_true', help='Run in headless mode (no GUI Browser)')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__, help='Show current version of pyxss')
    args = parser.parse_args()

    # Set stdout to unbuffered mode for immediate output
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        # Fallback for older Python versions - output is already flushed with flush=True
        pass

    if not args.silent:
        print(BANNER)

    # Register signal handler for CTRL+C
    signal.signal(signal.SIGINT, signal_handler)

    # Read all URLs from standard input
    urls = []
    try:
        for url in sys.stdin:
            url = url.strip()
            if url and (url.startswith("http://") or url.startswith("https://")):
                urls.append(url)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Closing all Chrome windows...", flush=True)
        shutdown_requested.set()
        with drivers_lock:
            for driver in list(active_drivers):
                try:
                    driver.quit()
                except Exception:
                    pass
        return
    
    if not urls:
        print("No valid URLs found in input.", flush=True)
        return
    
    total_urls = len(urls)
    
    # Open output file once if specified
    output_file = None
    file_lock = threading.Lock()
    if args.output:
        try:
            output_file = open(args.output, 'a', encoding='utf-8')
        except Exception as e:
            print(f"Error opening output file: {e}", flush=True)
            return
    
    # Statistics tracking
    stats = {
        'processed': 0,
        'vulnerable': 0,
        'not_vulnerable': 0,
        'lock': threading.Lock()
    }
    
    executor = None
    future_to_url = {}
    try:
        # Use ThreadPoolExecutor for parallel processing
        # Don't use context manager to have control over shutdown timing
        executor = ThreadPoolExecutor(max_workers=args.workers)
        
        # Submit all URLs for processing
        future_to_url = {
            executor.submit(process_url, url, args, file_lock, output_file, stats): url
            for url in urls
        }
        
        # Process results as they complete
        try:
            for future in as_completed(future_to_url):
                # Check if shutdown was requested
                if shutdown_requested.is_set():
                    break
                
                url = future_to_url[future]
                try:
                    result_type, result_msg = future.result()
                    
                    # Handle result
                    if result_msg:
                        if result_type:
                            print_result(result_type, result_msg, None, args)
                        else:
                            # Error message
                            print(result_msg, flush=True)
                            
                except Exception as e:
                    error_msg = f"URL: {url} - Exception in worker: {str(e)}"
                    print(error_msg, flush=True)
                    
        except KeyboardInterrupt:
            # KeyboardInterrupt caught during loop execution
            shutdown_requested.set()
                
    except KeyboardInterrupt:
        # KeyboardInterrupt caught during executor setup
        shutdown_requested.set()
        
    finally:
        # Handle shutdown if requested
        if shutdown_requested.is_set():
            print("\n\nInterrupted by user. Closing all Chrome windows...", flush=True)
            # Cancel all pending futures
            if future_to_url:
                for future in future_to_url:
                    try:
                        future.cancel()
                    except Exception:
                        pass
            # Shutdown executor immediately without waiting
            if executor:
                try:
                    executor.shutdown(wait=False)
                except Exception:
                    pass
        else:
            # Normal shutdown - wait for executor to finish
            if executor:
                try:
                    executor.shutdown(wait=True)
                except Exception:
                    pass
        
        # Close all remaining drivers
        with drivers_lock:
            for driver in list(active_drivers):
                try:
                    driver.quit()
                except Exception:
                    pass
        
        # Close output file
        if output_file:
            try:
                output_file.close()
            except Exception:
                pass
        
        # Exit immediately if shutdown was requested
        if shutdown_requested.is_set():
            sys.exit(0)


if __name__ == "__main__":
    main()
