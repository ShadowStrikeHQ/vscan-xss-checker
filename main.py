import argparse
import requests
from bs4 import BeautifulSoup
import logging
import urllib.parse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# XSS Payloads (extend as needed)
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "';alert('XSS');//"
]

def setup_argparse():
    """Sets up the argument parser for the command-line interface."""
    parser = argparse.ArgumentParser(description="vscan-xss-checker: Detects potential XSS vulnerabilities.")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("-p", "--payloads", nargs='+', help="Custom XSS payloads to use (optional).", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debugging).")
    return parser.parse_args()

def inject_payloads(url, payloads):
    """
    Injects XSS payloads into form fields and URL parameters.

    Args:
        url (str): The URL to scan.
        payloads (list): A list of XSS payloads to inject.

    Returns:
        list: A list of vulnerable URLs (if any are found).
    """
    vulnerable_urls = []
    try:
        # Check URL parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        for param in query_params:
            original_value = query_params[param][0]  # Get the first value
            for payload in payloads:
                # Create a new URL with the injected payload
                new_query_params = query_params.copy()
                new_query_params[param] = [payload] # Replace with the payload
                new_query = urllib.parse.urlencode(new_query_params, doseq=True)  # Encode back to string, doseq=True handles multiple values for a single key

                new_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))


                try:
                    response = requests.get(new_url)
                    response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

                    if payload in response.text:
                        logging.warning(f"Potential XSS vulnerability found in URL parameter '{param}': {new_url}")
                        vulnerable_urls.append(new_url)
                    elif "<script>" in response.text.lower() or "<img" in response.text.lower() or "<svg" in response.text.lower():
                        logging.warning(f"Potential XSS vulnerability (reflected script tag) found in URL parameter '{param}': {new_url}")
                        vulnerable_urls.append(new_url) # Consider it vulnerable even if the exact payload is not present, but potential harmful script tags are

                except requests.exceptions.RequestException as e:
                    logging.error(f"Error during request for URL parameter '{param}': {e}")


        # Check form fields
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise HTTPError for bad responses

            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', url)  # Default to the original URL if action is empty
                method = form.get('method', 'GET').upper()

                inputs = form.find_all('input')
                data = {}

                for input_field in inputs:
                    name = input_field.get('name')
                    if name:  # Only process fields with a name
                        data[name] = ""  # Set default to empty string

                # Inject payloads into the form data
                for payload in payloads:
                    for field in data:
                        data[field] = payload  # Inject the payload into each field, one by one

                        try:
                            if method == 'GET':
                                full_url = action + "?" + urllib.parse.urlencode(data)
                                response = requests.get(full_url)
                                response.raise_for_status()  # Raise HTTPError for bad responses

                                if payload in response.text:
                                    logging.warning(f"Potential XSS vulnerability found in form (GET, field '{field}'): {full_url}")
                                    vulnerable_urls.append(full_url)
                                elif "<script>" in response.text.lower() or "<img" in response.text.lower() or "<svg" in response.text.lower():
                                    logging.warning(f"Potential XSS vulnerability (reflected script tag) found in form (GET, field '{field}'): {full_url}")
                                    vulnerable_urls.append(full_url)
                            elif method == 'POST':
                                response = requests.post(action, data=data)
                                response.raise_for_status()  # Raise HTTPError for bad responses
                                if payload in response.text:
                                    logging.warning(f"Potential XSS vulnerability found in form (POST, field '{field}'): {action} (data: {data})")
                                    vulnerable_urls.append(action)
                                elif "<script>" in response.text.lower() or "<img" in response.text.lower() or "<svg" in response.text.lower():
                                    logging.warning(f"Potential XSS vulnerability (reflected script tag) found in form (POST, field '{field}'): {action} (data: {data})")
                                    vulnerable_urls.append(action)
                        except requests.exceptions.RequestException as e:
                            logging.error(f"Error during request for form (field '{field}'): {e}")
                        data[field] = ""  # Reset the field to an empty string for the next iteration
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching or parsing the initial page: {e}")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

    return vulnerable_urls


def main():
    """Main function to execute the XSS checker."""
    args = setup_argparse()

    if not args.url:
        logging.error("URL is required.")
        sys.exit(1)

    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        logging.error("URL must start with http:// or https://")
        sys.exit(1)

    payloads_to_use = args.payloads if args.payloads else XSS_PAYLOADS

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)  # Set logging to DEBUG for verbose output
        logging.debug(f"Scanning URL: {args.url}")
        logging.debug(f"Using payloads: {payloads_to_use}")

    vulnerable_urls = inject_payloads(args.url, payloads_to_use)

    if vulnerable_urls:
        print("\nVulnerabilities Found:")
        for url in vulnerable_urls:
            print(f"- {url}")
    else:
        print("\nNo vulnerabilities found.")


if __name__ == "__main__":
    main()