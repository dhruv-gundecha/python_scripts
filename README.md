# Python Security Scripts

This repository contains a set of Python scripts for educational and authorized cybersecurity testing. These tools demonstrate concepts like shell access, SQL injection, brute-force attacks, DLL injection, and keylogging.

## Table of Contents

- [Scripts Overview](#scripts-overview)
- [Installation](#installation)
- [Disclaimer](#disclaimer)
- [License](#license)

## Scripts Overview

- `encrypted_bind_shell.py`: Creates a encrypted bind shell for remote command execution.
- `blind_sqli.py`: Demonstrates a blind SQL injection based on conditional responses.
- `keylogger.py`: Captures keystrokes and stores them locally.
- `process_creation_and_shellcode_execution.py`: Runs raw shellcode in a new process.
- `remotedll.py`: Injects a DLL into a remote process by PID.
- `ssh_brute.py`: Performs SSH brute-force attacks using a given wordlist.
- `web_brute.py`: Brute-forces credentials on a web login form checking for a custom string in response.

## Installation

Clone the repository and install any required packages:

```bash
git clone https://github.com/dhruv-gundecha/python_scripts.git
cd python_scripts
pip install -r requirements.txt
