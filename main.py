import os
import logging
from ttkbootstrap import Window, ttk
from ttkbootstrap.constants import X, SUCCESS
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from tkinter import messagebox, StringVar, IntVar
import requests
import json

load_dotenv()

logging.basicConfig(
    filename="roblox_login.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY") or Fernet.generate_key().decode()

if not os.getenv("ENCRYPTION_KEY"):
    with open(".env", "a") as env_file:
        env_file.write(f"ENCRYPTION_KEY={ENCRYPTION_KEY}\n")

cipher_suite = Fernet(ENCRYPTION_KEY.encode())

def encrypt_text(text):
    """Encrypt sensitive text."""
    return cipher_suite.encrypt(text.encode()).decode()

def solve_captcha_with_anticaptcha(driver, api_key):
    """Solve CAPTCHA using AntiCaptcha."""
    try:
        site_key = driver.find_element(By.CLASS_NAME, "g-recaptcha").get_attribute("data-sitekey")
        current_url = driver.current_url
        logging.info("Fetching CAPTCHA solution from AntiCaptcha.")

        response = requests.post(
            "https://api.anti-captcha.com/createTask",
            json={
                "clientKey": api_key,
                "task": {
                    "type": "NoCaptchaTaskProxyless",
                    "websiteURL": current_url,
                    "websiteKey": site_key,
                },
            },
        )
        task_id = response.json().get("taskId")

        while True:
            result = requests.post(
                "https://api.anti-captcha.com/getTaskResult",
                json={"clientKey": api_key, "taskId": task_id},
            ).json()

            if result.get("status") == "ready":
                solution = result["solution"]["gRecaptchaResponse"]
                logging.info("CAPTCHA solved.")
                driver.execute_script(
                    'document.getElementById("g-recaptcha-response").innerHTML = arguments[0];',
                    solution,
                )
                break

        driver.find_element(By.ID, "login-button").click()
    except Exception as e:
        logging.error(f"Error solving CAPTCHA with AntiCaptcha: {str(e)}")

def solve_captcha_with_2captcha(driver, api_key):
    """Solve CAPTCHA using 2Captcha."""
    try:
        site_key = driver.find_element(By.CLASS_NAME, "g-recaptcha").get_attribute("data-sitekey")
        current_url = driver.current_url
        logging.info("Fetching CAPTCHA solution from 2Captcha.")

        response = requests.get(
            f"http://2captcha.com/in.php?key={api_key}&method=userrecaptcha&googlekey={site_key}&pageurl={current_url}"
        )
        captcha_id = response.text.split('|')[1]

        while True:
            result = requests.get(
                f"http://2captcha.com/res.php?key={api_key}&action=get&id={captcha_id}"
            ).text

            if result.startswith("OK|"):
                solution = result.split('|')[1]
                logging.info("CAPTCHA solved.")
                driver.execute_script(
                    'document.getElementById("g-recaptcha-response").innerHTML = arguments[0];',
                    solution,
                )
                break

        driver.find_element(By.ID, "login-button").click()
    except Exception as e:
        logging.error(f"Error solving CAPTCHA with 2Captcha: {str(e)}")

def solve_captcha_with_deathbycaptcha(driver, username, password):
    """Solve CAPTCHA using DeathByCaptcha."""
    try:
        site_key = driver.find_element(By.CLASS_NAME, "g-recaptcha").get_attribute("data-sitekey")
        current_url = driver.current_url
        logging.info("Fetching CAPTCHA solution from DeathByCaptcha.")

        response = requests.post(
            "http://api.dbcapi.me/api/captcha",
            auth=(username, password),
            data={
                "googlekey": site_key,
                "pageurl": current_url,
                "proxy": "",
                "proxytype": ""
            },
        )
        captcha_data = json.loads(response.text)
        solution = captcha_data.get("text")

        logging.info("CAPTCHA solved.")
        driver.execute_script(
            'document.getElementById("g-recaptcha-response").innerHTML = arguments[0];',
            solution,
        )
        driver.find_element(By.ID, "login-button").click()
    except Exception as e:
        logging.error(f"Error solving CAPTCHA with DeathByCaptcha: {str(e)}")

def click_accept_cookies_button(driver):
    """Click the cookie accept button if it appears."""
    try:
        cookie_button = WebDriverWait(driver, 5).until(
            EC.element_to_be_clickable((
                By.XPATH,
                "//button[contains(@class, 'cookie-btn') and (contains(text(), 'Allem zustimmen') or contains(text(), 'Accept All'))]"
            ))
        )
        cookie_button.click()
        logging.info("Cookie accept button clicked.")
    except Exception as e:
        logging.warning(f"Cookie accept button not found or could not be clicked: {e}")

def login_to_roblox(username, password, headless, save_credentials, file_name, captcha_provider, api_details):
    """Log into Roblox, handle CAPTCHA, and save cookies."""
    chrome_options = Options()
    if headless:
        chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--start-maximized")
    chrome_options.add_argument("--log-level=3")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)

    try:
        driver.get("https://www.roblox.com/login")
        click_accept_cookies_button(driver)

        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, "login-username")))

        driver.find_element(By.ID, "login-username").send_keys(username)
        driver.find_element(By.ID, "login-password").send_keys(password)
        click_accept_cookies_button(driver)  
        driver.find_element(By.ID, "login-button").click()

        if "captcha" in driver.page_source.lower():
            logging.info("CAPTCHA detected.")
            if captcha_provider == "AntiCaptcha":
                solve_captcha_with_anticaptcha(driver, api_details.get("anticaptcha_api_key"))
            elif captcha_provider == "2Captcha":
                solve_captcha_with_2captcha(driver, api_details.get("2captcha_api_key"))
            elif captcha_provider == "DeathByCaptcha":
                solve_captcha_with_deathbycaptcha(
                    driver,
                    api_details.get("dbc_username"),
                    api_details.get("dbc_password"),
                )
            else:
                messagebox.showinfo("CAPTCHA Required", "Complete the CAPTCHA manually in the browser.")

        cookies = driver.get_cookies()
        roblosecurity = next((cookie['value'] for cookie in cookies if cookie['name'] == '.ROBLOSECURITY'), None)

        if roblosecurity:
            with open(file_name, "w") as file:
                if save_credentials:
                    file.write(f"Username: {encrypt_text(username)}\nPassword: {encrypt_text(password)}\n")
                file.write(f"ROBLOSECURITY: {roblosecurity}\n")
            messagebox.showinfo("Success", "Login successful!")
        else:
            messagebox.showwarning("Warning", "ROBLOSECURITY cookie not found.")

    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
    finally:
        driver.quit()

def update_ui_fields(*args):
    """Update API fields dynamically based on CAPTCHA provider selection."""
    global api_key_label, api_key_entry, dbc_password_label, dbc_password_entry

    provider = captcha_provider_var.get()
    if provider == "None":
        api_key_label.grid_remove()
        api_key_entry.grid_remove()
        dbc_password_label.grid_remove()
        dbc_password_entry.grid_remove()
    elif provider in ["AntiCaptcha", "2Captcha"]:
        api_key_label.config(text=f"{provider} API Key:")
        api_key_label.grid(row=6, column=0, padx=10, pady=5, sticky="w")
        api_key_entry.grid(row=6, column=1, padx=10, pady=5, sticky="ew")
        dbc_password_label.grid_remove()
        dbc_password_entry.grid_remove()
    elif provider == "DeathByCaptcha":
        api_key_label.config(text="DeathByCaptcha Username:")
        api_key_label.grid(row=6, column=0, padx=10, pady=5, sticky="w")
        api_key_entry.grid(row=6, column=1, padx=10, pady=5, sticky="ew")
        dbc_password_label.grid(row=7, column=0, padx=10, pady=5, sticky="w")
        dbc_password_entry.grid(row=7, column=1, padx=10, pady=5, sticky="ew")

def create_ui():
    """Create the main UI for the application."""
    global captcha_provider_var, api_key_label, api_key_entry, dbc_password_label, dbc_password_entry

    app = Window(themename="solar")
    app.title("Roblox Login to Cookie - TheZ")
    app.geometry("600x350")
    app.columnconfigure(1, weight=1)
    app.iconbitmap("icon.ico")

    username_var = StringVar()
    password_var = StringVar()
    file_name_var = StringVar(value="roblox_cookie.txt")
    captcha_provider_var = StringVar(value="None")
    captcha_provider_var.trace("w", update_ui_fields)
    headless_var = IntVar(value=0)
    save_credentials_var = IntVar(value=0)
    api_key_var = StringVar()
    dbc_password_var = StringVar()

    ttk.Label(app, text="Roblox Login", font=("Helvetica", 16, "bold"))\
        .grid(row=0, column=0, columnspan=2, pady=10)
    
    ttk.Label(app, text="Join my Discord - TheZ").grid(row=0, column=0, padx=10, pady=5, sticky="w")

    ttk.Label(app, text="Username:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
    ttk.Entry(app, textvariable=username_var).grid(row=1, column=1, padx=10, pady=5, sticky="ew")

    ttk.Label(app, text="Password:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
    ttk.Entry(app, textvariable=password_var, show="*").grid(row=2, column=1, padx=10, pady=5, sticky="ew")

    ttk.Label(app, text="Output File Name:").grid(row=3, column=0, padx=10, pady=5, sticky="w")
    ttk.Entry(app, textvariable=file_name_var).grid(row=3, column=1, padx=10, pady=5, sticky="ew")

    ttk.Label(app, text="CAPTCHA Provider:").grid(row=4, column=0, padx=10, pady=5, sticky="w")
    ttk.OptionMenu(app, captcha_provider_var, "None", "AntiCaptcha", "2Captcha", "DeathByCaptcha")\
        .grid(row=4, column=1, padx=10, pady=5, sticky="ew")

    ttk.Checkbutton(app, text="Run in headless mode", variable=headless_var)\
        .grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="w")

    ttk.Checkbutton(app, text="Save credentials to file", variable=save_credentials_var)\
        .grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky="w")

    api_key_label = ttk.Label(app, text="")
    api_key_entry = ttk.Entry(app, textvariable=api_key_var)
    dbc_password_label = ttk.Label(app, text="Password:")
    dbc_password_entry = ttk.Entry(app, textvariable=dbc_password_var, show="*")

    ttk.Button(
        app,
        text="Login",
        bootstyle=SUCCESS,
        command=lambda: login_to_roblox(
            username_var.get(),
            password_var.get(),
            headless_var.get(),
            save_credentials_var.get(),
            file_name_var.get(),
            captcha_provider_var.get(),
            {
                "anticaptcha_api_key": api_key_var.get(),
                "2captcha_api_key": api_key_var.get(),
                "dbc_username": api_key_var.get(),
                "dbc_password": dbc_password_var.get(),
            },
        ),
    ).grid(row=8, column=0, columnspan=2, pady=20)

    app.mainloop()

if __name__ == "__main__":
    create_ui()
