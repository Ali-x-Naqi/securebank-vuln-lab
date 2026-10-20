# Natural walkthrough of the SAFE version blocking every attack (for recording).
import time, urllib.parse
from playwright.sync_api import sync_playwright

BASE = "http://localhost:3000"
def q(s): return BASE + "/search?q=" + urllib.parse.quote(s)

with sync_playwright() as p:
    br = p.chromium.launch(headless=False, slow_mo=450, args=["--start-maximized"])
    ctx = br.new_context(no_viewport=True)
    page = ctx.new_page()
    page.on("dialog", lambda d: (time.sleep(1.0), d.accept()))

    page.goto(BASE + "/login"); time.sleep(6)

    # login bypass now rejected
    page.fill("input[name=username]", "admin'-- ")
    page.fill("input[name=password]", "wrongpassword"); time.sleep(1.2)
    page.click("button[type=submit]"); page.wait_for_load_state("networkidle"); time.sleep(3)

    # proper login to reach the rest
    page.fill("input[name=username]", "admin")
    page.fill("input[name=password]", "Sup3rSecret!2026"); time.sleep(1)
    page.click("button[type=submit]"); page.wait_for_load_state("networkidle"); time.sleep(1.5)

    # reflected XSS now encoded (shown as text)
    xss = "<script>document.body.insertAdjacentHTML('afterbegin','<div>XSS</div>')</script>"
    page.goto(q(xss)); time.sleep(4)

    # UNION injection now returns no credentials
    page.goto(q("' UNION SELECT username,password,1 FROM users-- ")); time.sleep(2)
    page.mouse.wheel(0, 500); time.sleep(3)

    # DOM XSS now safe (fragment shown as text)
    page.goto(BASE + "/dom#" + urllib.parse.quote("<img src=x onerror=alert('DOM')>")); time.sleep(4)

    # CSRF: tokenless transfer is blocked (403)
    page.goto(BASE + "/transfer")
    page.evaluate("""() => { const f=document.createElement('form'); f.method='POST'; f.action='/transfer';
        f.innerHTML='<input name=to_account value=66666666><input name=amount value=5000>';
        document.body.appendChild(f); f.submit(); }""")
    page.wait_for_load_state("networkidle"); time.sleep(5)

    br.close()
    print("done")
