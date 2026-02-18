import requests
import base64
import json
import re
import time
import random

# --- تنظیمات شما ---
CHANNEL_ID = "@DarkRouteVPN"  # اسم کانال یا برند شما
AD_TEXT = "🔥 Join Our Channel 🔥"  # متن تبلیغاتی اول لیست
MAX_CONFIGS = 150  # تعداد کانفیگ‌ها (افزایش به ۱۵۰)

# لیست منابع (سورس‌ها رو زیاد کردم تا ۱۵۰ تا پر بشه)
SOURCES = [
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub2.txt",
    "https://raw.githubusercontent.com/Mohammadgb0078/IRV2ray/main/conf.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/EternityAir"
]

# تابع تبدیل کد کشور به ایموجی پرچم
def get_flag_emoji(country_code):
    if not country_code or country_code == 'XX': return "🚩"
    # تبدیل کد دو حرفی به ایموجی پرچم
    return chr(ord(country_code[0]) + 127397) + chr(ord(country_code[1]) + 127397)

# تابع پیدا کردن کشور از روی IP
def get_country(ip):
    try:
        # اگر IP لوکال بود چک نکن
        if ip.startswith("127.") or ip.startswith("192.168"): return "XX"
        
        # استفاده از API برای تشخیص کشور
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=3)
        if response.status_code == 200:
            return response.json().get('countryCode', 'XX')
    except:
        pass
    return "XX"

# پردازش کانفیگ‌های VMess
def process_vmess(config, index):
    try:
        b64_part = config[8:]
        # فیکس کردن پدینگ Base64
        missing_padding = len(b64_part) % 4
        if missing_padding: b64_part += '=' * (4 - missing_padding)
        
        decoded = base64.b64decode(b64_part).decode('utf-8')
        data = json.loads(decoded)
        
        # پیدا کردن کشور
        ip = data.get('add', '')
        port = data.get('port', '')
        
        # اگر IP خالی بود یا غیرمعتبر، رد کن
        if not ip: return None

        country = get_country(ip)
        flag = get_flag_emoji(country)
        
        # تغییر نام به فرمت: 🇩🇪 @DarkRouteVPN | 1
        data['ps'] = f"{flag} {CHANNEL_ID} | {index}"
        
        new_json = json.dumps(data)
        new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
        return "vmess://" + new_b64
    except:
        return None

# پردازش سایر پروتکل‌ها (Vless, Trojan, SS)
def process_vless_trojan(config, index):
    try:
        # پیدا کردن IP با Regex
        match = re.search(r'@(.*?):', config)
        if not match:
             match = re.search(r'://(.*?):', config)
        
        ip = match.group(1) if match else ""
        
        if not ip: return None
        
        country = "XX"
        if not ip.startswith(('[', 'www')): 
            country = get_country(ip)
        
        flag = get_flag_emoji(country)
        
        new_name = f"{flag} {CHANNEL_ID} | {index}"
        
        # جایگزینی اسم
        if '#' in config:
            return config.split('#')[0] + f"#{new_name}"
        else:
            return config + f"#{new_name}"
    except:
        return None

def main():
    final_configs = []
    
    # 1. ساخت کانفیگ تبلیغاتی (لینک جوین)
    ad_vmess = {
        "v": "2", "ps": AD_TEXT, "add": "1.1.1.1", "port": "443", 
        "id": "3b20757d-127e-4008-8631-1e967d7164f5", "net": "tcp", "type": "none"
    }
    ad_b64 = base64.b64encode(json.dumps(ad_vmess).encode('utf-8')).decode('utf-8')
    final_configs.append("vmess://" + ad_b64)

    print("Fetching configs from sources...")
    raw_configs = []
    
    # دانلود از تمام سورس‌ها
    for source in SOURCES:
        try:
            print(f"Downloading from: {source}")
            resp = requests.get(source, timeout=10)
            content = resp.text.strip()
            
            # اگر کل محتوا Base64 بود، دیکود کن
            if "vmess://" not in content and "vless://" not in content:
                try:
                    content = base64.b64decode(content).decode('utf-8')
                except: pass
            
            lines = content.splitlines()
            raw_configs.extend(lines)
        except Exception as e:
            print(f"Error fetching source: {e}")

    # حذف تکراری‌ها و مخلوط کردن برای تنوع
    unique_configs = list(set(raw_configs))
    random.shuffle(unique_configs) # شافل میکنیم که کانفیگ‌های متنوع بالا بیان

    print(f"Total unique configs found: {len(unique_configs)}")
    print(f"Processing top {MAX_CONFIGS} configs (This may take a few minutes)...")
    
    count = 1
    processed_configs = []

    for conf in unique_configs:
        if count > MAX_CONFIGS: break
        
        conf = conf.strip()
        if not conf: continue
        
        # فیلتر کردن کانفیگ‌های خیلی طولانی یا خراب
        if len(conf) > 2000: continue

        new_conf = None
        
        # پردازش بر اساس نوع
        if conf.startswith("vmess://"):
            new_conf = process_vmess(conf, count)
        elif conf.startswith(("vless://", "trojan://", "ss://")):
            new_conf = process_vless_trojan(conf, count)
            
        if new_conf:
            processed_configs.append(new_conf)
            print(f"Processed #{count} - Protocol: {conf.split(':')[0]}")
            count += 1
            # مکث ۱.۵ ثانیه‌ای برای جلوگیری از بن شدن IP توسط سایت تشخیص کشور
            # برای ۱۵۰ کانفیگ حدود ۴ دقیقه طول میکشد
            time.sleep(1.3) 

    # اضافه کردن به لیست نهایی (اول تبلیغ، بعد کانفیگ‌ها)
    final_configs.extend(processed_configs)

    # ذخیره در فایل متنی
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_configs))
        
    # ذخیره در فایل Base64 (لینک اصلی)
    final_b64 = base64.b64encode("\n".join(final_configs).encode('utf-8')).decode('utf-8')
    with open("sub_base64.txt", "w", encoding="utf-8") as f:
        f.write(final_b64)
        
    print("Done! Files saved.")

if __name__ == "__main__":
    main()
