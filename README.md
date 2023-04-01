# HTTPHeadersCheck
Check the Request and Response Headers of a Web Server and/or Website, to figure out if there are any misconfigurations in the headers. A great test when performing a security assessment during web server and website penetration testing. A typical footprinting and OSINT tool.

## How this script works?
- The user is asked for input on a web server and website to test the headers on.
- The script shows and returns the REQUEST HEADERS from the web server and the RESPONSE HEADERS from the web server.
- The script also shows and returns any possible Security Misconfigurations in the headers.

## Requirements

Install your libraries:
```bash
pip install requests
```

## Permissions

Ensure you give the script permissions to execute. Do the following from the terminal:
```bash
sudo chmod +x HTTPHeadersCheck.py
```

## Usage
```bash
sudo python3 HTTPHeadersCheck.py
```

## Example script
```python
import requests

# Define a class to encapsulate website analysis logic
class WebsiteAnalyzer:
    def __init__(self, website):
        # Add the prefix to the website URL if needed
        self.website = self.add_prefix(website)
        # Set the User-Agent header for the GET request
        self.headers = {'User-Agent': 'Mozilla/5.0'}
        # Make a GET request to the website
        self.response = requests.get(self.website, headers=self.headers)

    def add_prefix(self, website):
        # Add the 'http://' or 'https://' prefix to the website URL if needed
        if not website.startswith("http://") and not website.startswith("https://"):
            website = "https://" + website
        return website

    def print_headers(self, headers, title):
        # Print the headers with a title
        print(title)
        for header, value in headers.items():
            print("{}: {}".format(header, value))
        print("----------------------------------------")

    def check_security_headers(self):
        # Check for security misconfigurations in the headers
        print("Checking for security misconfigurations in the headers...")
        # Check for the X-Content-Type-Options header
        if "X-Content-Type-Options" not in self.response.headers:
            print("{} header not found - may be vulnerable to MIME type sniffing attacks".format("X-Content-Type-Options"))
        # Check for the X-XSS-Protection header
        if "X-XSS-Protection" not in self.response.headers:
            print("{} header not found - may be vulnerable to cross-site scripting attacks".format("X-XSS-Protection"))
        # Check for the X-Frame-Options header
        if "X-Frame-Options" not in self.response.headers:
            print("{} header not found - may be vulnerable to clickjacking attacks".format("X-Frame-Options"))
        # Check for the Content-Security-Policy header
        if not any(header in self.response.headers for header in ("Content-Security-Policy", "X-Content-Security-Policy", "X-WebKit-CSP")):
            print("{} header not found - may be vulnerable to cross-site scripting and injection attacks".format("Content-Security-Policy"))
        # Check for the Server header
        if "Server" in self.response.headers:
            print("{} header found - may reveal sensitive information about the server".format("Server"))
        # Check for the X-Powered-By header
        if "X-Powered-By" in self.response.headers:
            print("{} header found - may reveal sensitive information about the server".format("X-Powered-By"))
        # Check for the Set-Cookie header
        if "Set-Cookie" in self.response.headers:
            print("{} header found - may be vulnerable to session hijacking attacks".format("Set-Cookie"))
        # Check for the Access-Control-Allow-Origin header
        if "Access-Control-Allow-Origin" in self.response.headers:
            print("{} header found - may be vulnerable to cross-domain attacks".format("Access-Control-Allow-Origin"))

    def analyze_website(self):
        # Analyze the website
        print("Sending request to {}...".format(self.website))
        print("Response received from {}.".format(self.website))
        print("----------------------------------------")
        self.print_headers(self.response.request.headers, "Request headers:")
        self.print_headers(self.response.headers, "Response headers:")
        self.check_security_headers()

if __name__ == "__main__":
    # Request the website from the user
    website = input("Enter a website to test (without the 'http://' or 'https://' prefix): ")
    # Create a WebsiteAnalyzer object for the website
    analyzer = WebsiteAnalyzer(website)
    # Analyze the website
    analyzer.analyze_website()
```

## License Information

This library is released under the [Creative Commons ShareAlike 4.0 International license](https://creativecommons.org/licenses/by-sa/4.0/). You are welcome to use this library for commercial purposes. For attribution, we ask that when you begin to use our code, you email us with a link to the product being created and/or sold. We want bragging rights that we helped (in a very small part) to create your 9th world wonder. We would like the opportunity to feature your work on our homepage.
