import requests
import base64
import json
import re
import time
import random
import os

# --- تنظیمات شما ---
CHANNEL_ID = "@DarkRouteVPN"  
AD_TEXT = "🔥 عضو کانال بشید 🔥"  
MAX_CONFIGS = 3000  # محدودیت تعداد کانفیگ‌ها
CACHE_FILE = "ip_cache.json" # فایل ذخیره دائمی کشورها

# لیست کامل سورس‌ها
SOURCES = [
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/vless_base64.txt",
    "https://raw.githubusercontent.com/Mohammadgb0078/IRV2ray/main/conf.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/EternityAir"
]

# لود کردن کش از فایل
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            ip_cache = json.load(f)
        print(f"[*] Loaded {len(ip_cache)} IPs from cache file.")
    except:
        ip_cache = {}
else:
    ip_cache = {}

def save_cache():
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(ip_cache, f)
    print(f"[*] Saved {len(ip_cache)} IPs to cache file.")

def get_flag_emoji(country_code):
    if not country_code or country_code == 'XX': return "🚩"
    return chr(ord(country_code[0]) + 127397) + chr(ord(country_code[1]) + 127397)

def get_country(ip):
    if ip in ip_cache:
        return ip_cache[ip]

    try:
        if ip.startswith("127.") or ip.startswith("192.168"): 
            ip_cache[ip] = "XX"
            return "XX"
        
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5)
        if response.status_code == 200:
            country = response.json().get('countryCode', 'XX')
            ip_cache[ip] = country
            time.sleep(1.5)
            return country
    except:
        pass
    
    ip_cache[ip] = "XX"
    return "XX"

def process_vmess(config, index):
    try:
        b64_part = config[8:]
        missing_padding = len(b64_part) % 4
        if missing_padding: b64_part += '=' * (4 - missing_padding)
        
        decoded = base64.b64decode(b64_part).decode('utf-8')
        data = json.loads(decoded)
        
        ip = data.get('add', '')
        if not ip: return None

        country = get_country(ip)
        flag = get_flag_emoji(country)
        
        data['ps'] = f"{flag} {CHANNEL_ID} | {index}"
        
        new_json = json.dumps(data)
        new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
        return "vmess://" + new_b64
    except:
        return None

def process_vless_trojan(config, index):
    try:
        match = re.search(r'@([^:]+):', config)
        if not match:
             match = re.search(r'://([^:]+):', config)
        
        ip = match.group(1) if match else ""
        if not ip: return None
        
        country = "XX"
        if not ip.startswith(('[', 'www')) and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip): 
            country = get_country(ip)
        
        flag = get_flag_emoji(country)
        new_name = f"{flag} {CHANNEL_ID} | {index}"
        
        if '#' in config:
            return config.split('#')[0] + f"#{new_name}"
        else:
            return config + f"#{new_name}"
    except:
        return None

def main():
    final_configs = []
    
    ad_vmess = {
        "v": "2", "ps": AD_TEXT, "add": "1.1.1.1", "port": "443", 
        "id": "3b20757d-127e-4008-8631-1e967d7164f5", "net": "tcp", "type": "none"
    }
    ad_b64 = base64.b64encode(json.dumps(ad_vmess).encode('utf-8')).decode('utf-8')
    final_configs.append("vmess://" + ad_b64)

    print("[*] Fetching configs from sources...")
    raw_configs = []
    
    for source in SOURCES:
        try:
            print(f"[+] Downloading: {source}")
            resp = requests.get(source, timeout=15)
            content = resp.text.strip()
            
            if "vmess://" not in content and "vless://" not in content:
                try:
                    content = base64.b64decode(content).decode('utf-8')
                except: pass
            
            lines = content.splitlines()
            raw_configs.extend(lines)
        except Exception as e:
            print(f"[-] Error: {e}")

    unique_configs = list(set(raw_configs))
    random.shuffle(unique_configs)

    print(f"\n[*] Total unique configs found: {len(unique_configs)}")
    print(f"[*] Processing top {MAX_CONFIGS} configs...\n")
    
    count = 1
    processed_configs = []

    for conf in unique_configs:
        if count > MAX_CONFIGS: 
            break
            
        conf = conf.strip()
        if not conf or len(conf) > 2000: continue

        new_conf = None
        
        if conf.startswith("vmess://"):
            new_conf = process_vmess(conf, count)
        elif conf.startswith(("vless://", "trojan://", "ss://")):
            new_conf = process_vless_trojan(conf, count)
            
        if new_conf:
            processed_configs.append(new_conf)
            if count % 100 == 0:
                print(f"[~] Processed {count} configs so far...")
            count += 1

    final_configs.extend(processed_configs)

    print("\n[*] Saving configs...")
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_configs))
        
    final_b64 = base64.b64encode("\n".join(final_configs).encode('utf-8')).decode('utf-8')
    with open("sub_base64.txt", "w", encoding="utf-8") as f:
        f.write(final_b64)
        
    # ذخیره فایل کش
    save_cache()
    print(f"[+] Done! Processed {count-1} configs.")

if __name__ == "__main__":
    main()
