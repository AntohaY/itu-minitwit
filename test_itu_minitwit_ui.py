"""
UI and end-to-end tests for ITU MiniTwit.

Origin:
    This file is based on the Selenium test that was offered in Session 7.

Refactor note:
    The original Session 7 test targeted the legacy Flask implementation.
    This version was refactored to match the current itu-minitwit architecture
    (Go web app + MongoDB + current routes/templates) and to run in local and CI
    environments via environment-variable configuration.

Typical local run:
    make ui-e2e

Direct run:
    GECKODRIVER_PATH=/opt/homebrew/bin/geckodriver \
    python -m pytest -v test_itu_minitwit_ui.py
"""

import os
import uuid

import pymongo
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options


GUI_URL = os.getenv("MINITWIT_GUI_URL", "http://localhost:8080/register")
DB_URL = os.getenv("MINITWIT_DB_URL", "mongodb://localhost:27017/test")
GECKODRIVER_PATH = os.getenv("GECKODRIVER_PATH", "./geckodriver")
HEADLESS = os.getenv("MINITWIT_HEADLESS", "1").strip().lower() not in {"0", "false", "no"}
BASE_URL = GUI_URL.rsplit("/register", 1)[0]


def _unique_token(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _mongo_client():
    return pymongo.MongoClient(DB_URL, serverSelectionTimeoutMS=5000)


def _new_driver():
    firefox_options = Options()
    if HEADLESS:
        firefox_options.add_argument("--headless")
    return webdriver.Firefox(service=Service(GECKODRIVER_PATH), options=firefox_options)


def _register_user_via_gui(driver, data):
    driver.get(GUI_URL)

    wait = WebDriverWait(driver, 5)
    wait.until(EC.presence_of_element_located((By.NAME, "username")))

    driver.find_element(By.NAME, "username").send_keys(data[0])
    driver.find_element(By.NAME, "email").send_keys(data[1])
    driver.find_element(By.NAME, "password").send_keys(data[2])
    driver.find_element(By.NAME, "password2").send_keys(data[3])

    driver.find_element(By.CSS_SELECTOR, "form[action='/register'] button[type='submit']").click()

    wait.until(EC.url_contains("/login"))
    return driver.current_url


def _login_user_via_gui(driver, username, password):
    driver.get(f"{BASE_URL}/login")

    wait = WebDriverWait(driver, 8)
    wait.until(EC.presence_of_element_located((By.NAME, "username")))

    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "password").send_keys(password)
    driver.find_element(By.CSS_SELECTOR, "form[action='/login'] button[type='submit']").click()

    wait.until(EC.url_to_be(f"{BASE_URL}/"))
    return driver.current_url


def _seed_user(db_client, username, email=None, password="secure123"):
    user_doc = {
        "username": username,
        "email": email or f"{username}@example.test",
        "pw": password,
        "hashedpw": password,
    }
    result = db_client.test.user.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id
    return user_doc


def _cleanup_test_data(db_client, usernames=None, message_prefixes=None):
    usernames = usernames or []
    message_prefixes = message_prefixes or []

    users = list(db_client.test.user.find({"username": {"$in": usernames}}, {"_id": 1, "username": 1}))
    user_ids = [u["_id"] for u in users]

    if user_ids:
        db_client.test.follower.delete_many({"$or": [{"who_id": {"$in": user_ids}}, {"whom_id": {"$in": user_ids}}]})
        db_client.test.message.delete_many({"author_id": {"$in": user_ids}})

    if message_prefixes:
        for prefix in message_prefixes:
            db_client.test.message.delete_many({"text": {"$regex": f"^{prefix}"}})

    if usernames:
        db_client.test.user.delete_many({"username": {"$in": usernames}})


def _get_user_by_name(db_client, name):
    return db_client.test.user.find_one({"username": name})


def test_register_user_via_gui():
    """
    This is a UI test. It only interacts with the UI that is rendered in the browser and checks that visual
    responses that users observe are displayed.
    """
    username = _unique_token("ui_register")
    db_client = _mongo_client()
    try:
        with _new_driver() as driver:
            current_url = _register_user_via_gui(driver, [username, f"{username}@example.test", "secure123", "secure123"])
        assert "/login" in current_url
    finally:
        _cleanup_test_data(db_client, usernames=[username])


def test_register_user_via_gui_and_check_db_entry():
    """
    This is an end-to-end test. Before registering a user via the UI, it checks that no such user exists in the
    database yet. After registering a user, it checks that the respective user appears in the database.
    """
    username = _unique_token("e2e_register")
    db_client = _mongo_client()
    try:
        with _new_driver() as driver:
            assert _get_user_by_name(db_client, username) is None

            current_url = _register_user_via_gui(driver, [username, f"{username}@example.test", "secure123", "secure123"])
            assert "/login" in current_url

            assert _get_user_by_name(db_client, username)["username"] == username
    finally:
        _cleanup_test_data(db_client, usernames=[username])


def test_login_and_logout_ui_flow():
    username = _unique_token("ui_login")
    db_client = _mongo_client()

    try:
        _seed_user(db_client, username, password="secure123")

        with _new_driver() as driver:
            _login_user_via_gui(driver, username, "secure123")

            wait = WebDriverWait(driver, 8)
            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "a[href='/logout']")))
            assert f"Sign out [{username}]" in driver.page_source

            driver.find_element(By.CSS_SELECTOR, "a[href='/logout']").click()
            wait.until(EC.url_to_be(f"{BASE_URL}/"))
            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "a[href='/login']")))

            page = driver.page_source
            assert "Sign In" in page
            assert "Sign Up" in page
            assert "Sign out" not in page
    finally:
        _cleanup_test_data(db_client, usernames=[username])


def test_register_duplicate_username_validation():
    username = _unique_token("dup_user")
    db_client = _mongo_client()

    try:
        _seed_user(db_client, username, password="secure123")

        with _new_driver() as driver:
            driver.get(GUI_URL)
            wait = WebDriverWait(driver, 8)
            wait.until(EC.presence_of_element_located((By.NAME, "username")))

            driver.find_element(By.NAME, "username").send_keys(username)
            driver.find_element(By.NAME, "email").send_keys(f"{username}@example.test")
            driver.find_element(By.NAME, "password").send_keys("secure123")
            driver.find_element(By.NAME, "password2").send_keys("secure123")
            driver.find_element(By.CSS_SELECTOR, "form[action='/register'] button[type='submit']").click()

            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".alert")))
            assert "The username is already taken" in driver.page_source

            users = list(db_client.test.user.find({"username": username}))
            assert len(users) == 1
    finally:
        _cleanup_test_data(db_client, usernames=[username])


def test_post_message_via_ui_and_check_db_entry():
    username = _unique_token("msg_user")
    message_text = f"E2E_MSG_{_unique_token('post')}"
    db_client = _mongo_client()

    try:
        user_doc = _seed_user(db_client, username, password="secure123")

        with _new_driver() as driver:
            _login_user_via_gui(driver, username, "secure123")

            wait = WebDriverWait(driver, 8)
            wait.until(EC.presence_of_element_located((By.NAME, "text")))
            driver.find_element(By.NAME, "text").send_keys(message_text)
            driver.find_element(By.CSS_SELECTOR, "form[action='/add_message'] button[type='submit']").click()

            wait.until(EC.url_to_be(f"{BASE_URL}/"))
            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".list-group-item")))

            assert message_text in driver.page_source

            db_msg = db_client.test.message.find_one({"text": message_text, "author_id": user_doc["_id"]})
            assert db_msg is not None
    finally:
        _cleanup_test_data(db_client, usernames=[username], message_prefixes=["E2E_MSG_"])


def test_follow_unfollow_via_ui_and_check_db_entry():
    follower_username = _unique_token("follower")
    target_username = _unique_token("target")
    db_client = _mongo_client()

    try:
        follower_doc = _seed_user(db_client, follower_username, password="secure123")
        target_doc = _seed_user(db_client, target_username, password="secure123")

        with _new_driver() as driver:
            _login_user_via_gui(driver, follower_username, "secure123")

            wait = WebDriverWait(driver, 8)
            driver.get(f"{BASE_URL}/user/{target_username}")
            follow_selector = f"a[href='/user/follow/{target_username}']"
            unfollow_selector = f"a[href='/user/unfollow/{target_username}']"

            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, follow_selector)))
            driver.find_element(By.CSS_SELECTOR, follow_selector).click()

            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, unfollow_selector)))
            relation = db_client.test.follower.find_one({"who_id": follower_doc["_id"], "whom_id": target_doc["_id"]})
            assert relation is not None

            driver.find_element(By.CSS_SELECTOR, unfollow_selector).click()
            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, follow_selector)))

            relation = db_client.test.follower.find_one({"who_id": follower_doc["_id"], "whom_id": target_doc["_id"]})
            assert relation is None
    finally:
        _cleanup_test_data(db_client, usernames=[follower_username, target_username])
