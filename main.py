import requests
import base64
import json
import re
import time
import sys

# --- تنظیمات شما ---
CHANNEL_ID = "@DarkRouteVPN"
AD_TEXT = "🔥 Join Our Channel 🔥"  # متنی که اول لیست میاد
MAX_CONFIGS = 60  # تعداد کانفیگ‌هایی که چک کنه (زیاد نذار چون طول میکشه)

# لیست منابع (سورس‌ها)
SOURCES = [
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt",
    "https://raw.githubusercontent.com/Mohammadgb0078/IRV2ray/main/conf.txt"
]

# تابع تبدیل کد کشور به ایموجی پرچم
def get_flag_emoji(country_code):
    if not country_code: return "🚩"
    return chr(ord(country_code[0]) + 127397) + chr(ord(country_code[1]) + 127397)

# تابع پیدا کردن کشور از روی IP
def get_country(ip):
    try:
        # استفاده از API رایگان (با محدودیت، برای همین دیلی میذاریم)
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=3)
        if response.status_code == 200:
            return response.json().get('countryCode', 'XX')
    except:
        pass
    return "XX"

def process_vmess(config, index):
    try:
        b64_part = config[8:]
        missing_padding = len(b64_part) % 4
        if missing_padding: b64_part += '=' * (4 - missing_padding)
        
        decoded = base64.b64decode(b64_part).decode('utf-8')
        data = json.loads(decoded)
        
        # پیدا کردن کشور
        ip = data.get('add', '')
        country = get_country(ip)
        flag = get_flag_emoji(country)
        
        # تغییر نام
        data['ps'] = f"{flag} {CHANNEL_ID} | {index}"
        
        new_json = json.dumps(data)
        new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
        return "vmess://" + new_b64
    except:
        return None

def process_vless_trojan(config, index):
    try:
        # استخراج IP با Regex
        # فرمت معمول: vless://uuid@ip:port...
        match = re.search(r'@(.*?):', config)
        if not match:
             # شاید فرمت بدون @ باشه
             match = re.search(r'://(.*?):', config)
        
        ip = match.group(1) if match else ""
        
        country = "XX"
        if ip and not ip.startswith(('[', 'www')): # اگه دامین نباشه و IP باشه دقیقتره
            country = get_country(ip)
        
        flag = get_flag_emoji(country)
        
        # ساخت اسم جدید
        new_name = f"{flag} {CHANNEL_ID} | {index}"
        
        # جایگزینی اسم در کانفیگ (بعد از #)
        if '#' in config:
            return config.split('#')[0] + f"#{new_name}"
        else:
            return config + f"#{new_name}"
    except:
        return None

def main():
    final_configs = []
    
    # 1. اضافه کردن کانفیگ تبلیغاتی (یه کانفیگ فیک که فقط متنه)
    # این تکنیک برای نمایش پیام در بالای لیست استفاده میشه
    ad_vmess = {
        "v": "2", "ps": AD_TEXT, "add": "127.0.0.1", "port": "443", 
        "id": "00000000-0000-0000-0000-000000000000", "net": "tcp", "type": "none"
    }
    ad_b64 = base64.b64encode(json.dumps(ad_vmess).encode('utf-8')).decode('utf-8')
    final_configs.append("vmess://" + ad_b64)

    print("Fetching configs...")
    raw_configs = []
    
    # جمع‌آوری کانفیگ‌ها
    for source in SOURCES:
        try:
            resp = requests.get(source, timeout=10)
            content = resp.text.strip()
            
            # دیکود اولیه اگر کل فایل بیس64 باشه
            if "vmess://" not in content and "vless://" not in content:
                try:
                    content = base64.b64decode(content).decode('utf-8')
                except: pass
            
            lines = content.splitlines()
            raw_configs.extend(lines)
        except:
            continue

    # پردازش و تغییر نام
    print(f"Processing configs (Max: {MAX_CONFIGS})...")
    count = 1
    
    # حذف تکراری‌ها با set
    unique_configs = list(set(raw_configs))
    
    for conf in unique_configs:
        if count > MAX_CONFIGS: break
        
        conf = conf.strip()
        if not conf: continue
        
        new_conf = None
        
        # تشخیص نوع و پردازش
        if conf.startswith("vmess://"):
            new_conf = process_vmess(conf, count)
        elif conf.startswith(("vless://", "trojan://", "ss://")):
            new_conf = process_vless_trojan(conf, count)
            
        if new_conf:
            final_configs.append(new_conf)
            print(f"Processed #{count}")
            count += 1
            # مکث کوتاه برای جلوگیری از بن شدن IP توسط سایت تشخیص کشور
            time.sleep(1.2) 

    # ذخیره فایل‌ها
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_configs))
        
    final_b64 = base64.b64encode("\n".join(final_configs).encode('utf-8')).decode('utf-8')
    with open("sub_base64.txt", "w", encoding="utf-8") as f:
        f.write(final_b64)
        
    print("Done!")

if __name__ == "__main__":
    main()
