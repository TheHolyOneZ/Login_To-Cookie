# Login_To-Cookie (Doesnt work anymore)
Logs in with your Roblox username and password, and outputs your session cookie (ROBLOSECURITY), along with the option to encrypt and save your username and password.

[Join My Discord](https://discord.gg/zsGTqgnsmK)

This is a Python application that automates logging into Roblox accounts, handles CAPTCHA verification using third-party services (AntiCaptcha, 2Captcha, or DeathByCaptcha), and saves the session cookie for future use. It features a graphical user interface built using `ttkbootstrap`.

## Features
- **Automated Login**: Log into Roblox accounts automatically using your username and password.
- **CAPTCHA Handling**: Solves CAPTCHAs using services like AntiCaptcha, 2Captcha, and DeathByCaptcha.
- **Save Cookies**: Saves the `.ROBLOSECURITY` cookie, which can be used for maintaining a logged-in session.
- **Graphical User Interface**: Easy-to-use UI with the option to run in headless mode (no browser UI).

## Requirements
This application requires the following Python packages:

- `selenium`
- `webdriver-manager`
- `ttkbootstrap`
- `cryptography`
- `requests`
- `python-dotenv`
- `pillow` 

You can install these dependencies using the following:

### Installing Dependencies
Run the following command to install the required Python libraries:




```bash
pip install -r requirements.txt


