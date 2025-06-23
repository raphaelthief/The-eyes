import asyncio, socket, os, sys, subprocess, importlib.util, dnstwist, whois, requests
from telethon.sync import TelegramClient
from telethon.tl.functions.messages import GetDialogsRequest
from telethon.tl.types import InputPeerEmpty
from datetime import datetime, timedelta, timezone
from colorama import init, Fore, Style
from dnstwist import devnull


############ API & co ############
api_id = #Your telegram ID
api_hash = #'Your telegram token hash'
client = TelegramClient('session_name', api_id, api_hash)


############ Form & co ############
init() # Init colorama

M = Fore.MAGENTA
W = Fore.WHITE
R = Fore.RED
Y = Fore.YELLOW
G = Fore.GREEN
C = Fore.CYAN

banner = rf'''
{M}   _______  __              {G}  
{M}  |_     _||  |--..-----.   {G}.-----..--.--..-----..-----.
{M}    |   |  |     ||  -__|   {G}|  -__||  |  ||  -__||__ --|
{M}    |___|  |__|__||_____|   {G}|_____||___  ||_____||_____|
{M}                            {G}       |_____|{Y}<{C}raphaelthief{Y}>

'''


############ HTML Report ############
def generate_telegram_html_report(active_groups, inactive_groups, keyword_hits, keywords, inactive_days, message_days, max_messages):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Telegram Intelligence Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f5f5f5;
        }}
        h1, h2 {{
            color: #4B0082;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }}
        th, td {{
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left;
        }}
        th {{
            background: #eee;
        }}
        .inactive {{
            color: #a00;
        }}
        .active {{
            color: #080;
        }}
        .keyword {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 10px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <h1>Telegram Intelligence Report</h1>
    <p><strong>Generated on:</strong> {now_str}</p>
    <p><strong>Inactive threshold:</strong> {inactive_days} days</p>
    <p><strong>Message scan threshold:</strong> {message_days} days</p>
    <p><strong>Max messages scanned per group:</strong> {max_messages}</p>
    <p><strong>Keywords:</strong> {', '.join(escape(k) for k in keywords)}</p>

    <h2>Inactive Groups (≥ {inactive_days} days or no messages)</h2>
    <table>
        <tr><th>Group Name</th><th>Last Message</th></tr>"""
    for g, date in inactive_groups:
        date_str = date.strftime('%Y-%m-%d %H:%M') if date else "No messages"
        html += f"<tr><td class='inactive'>{escape(g.name)}</td><td>{escape(date_str)}</td></tr>"

    html += f"""</table>
    <h2>Active Groups (&lt; {inactive_days} days)</h2>
    <table>
        <tr><th>Group Name</th><th>Last Message</th></tr>"""
    for g, date in active_groups:
        html += f"<tr><td class='active'>{escape(g.name)}</td><td>{date.strftime('%Y-%m-%d %H:%M')}</td></tr>"

    html += "</table>"

    html += "<h2>Keyword Hits</h2>"
    if not keyword_hits:
        html += "<p>No keyword matches found in active groups.</p>"
    else:
        for group_name, messages in keyword_hits.items():
            html += f"<h3>{escape(group_name)}</h3>"
            for msg in messages:
                highlighted_text = escape(msg['text'])
                for kw in keywords:
                    highlighted_text = re.sub(f"(?i)({re.escape(kw)})", r"<span style='color:red; font-weight:bold;'>\1</span>", highlighted_text)
                html += f"<div class='keyword'><strong>{msg['date']}</strong><br>{highlighted_text}</div>"

    html += "</body></html>"

    timestamp = datetime.now().strftime("%Y.%m.%d_%Hh%M")
    filename = f"telegram_report_{timestamp}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n{M}[✓] {G}HTML report generated: {C}{filename}")


############ Telegram ############
def get_threshold_days():
    try:
        days = int(input(f" {G}Enter the number of days to consider a group inactive (default: 10) : ").strip() or "10")
        return days
    except ValueError:
        print(f"{M}[!] {R}Invalid input, defaulting to 10 days.")
        return 10

def get_message_days():
    try:
        days = int(input(f" {G}Enter how many days back to scan messages (default: 10) : ").strip() or "10")
        return days
    except ValueError:
        print(f"{M}[!] {R}Invalid input, defaulting to 10 days.")
        return 10

def get_max_messages():
    try:
        max_m = int(input(f" {G}Max messages to scan per group (default: 1000) : ").strip() or "1000")
        return max_m
    except ValueError:
        print(f"{M}[!] {R}Invalid input, defaulting to 1000 messages.")
        return 1000


def get_keywords():
    print(f"\n{M}[!] {G}🔍 Choose keyword input method :")
    print(f" {C}1. {G}Enter manually")
    print(f" {C}2. {G}Load from file (e.g., keywords.txt)")
    
    choice = input(f" {G}Select (1 or 2) : ").strip()

    if choice == "1":
        print(" Enter keywords separated by commas (e.g., intel, breach, poc)")
        manual_input = input(f" {G}Keywords : {C}").strip()
        return [kw.strip() for kw in manual_input.split(",") if kw.strip()]
    
    elif choice == "2":
        filepath = input(f"{M}[?] {G}Enter path to keyword file (default : keywords.txt) : ").strip()
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{M}[!] {R}File not found : {filepath}")
            return []
    else:
        print(f"{M}[!] {R}Invalid choice")
        return []

keyword_hits = {}

async def telegram(keywords, inactive_days, message_days, active_threshold, message_threshold, max_messages):
    await client.start()
    print(f"\n{M}[!] {G}🔗 Connected to Telegram")

    dialogs = await client.get_dialogs(limit=300)
    groups = [dialog for dialog in dialogs if dialog.is_group or dialog.is_channel]

    active_groups = []
    inactive_groups = []

    for group in groups:
        try:
            messages = await client.get_messages(group.entity, limit=1)
            if messages:
                last_date = messages[0].date
                if last_date > active_threshold:
                    active_groups.append((group, last_date))
                else:
                    inactive_groups.append((group, last_date))
            else:
                inactive_groups.append((group, None))
        except Exception as e:
            print(f"{M}[!] {R}Cannot access {group.name or 'Unknown'} : {e}")
            inactive_groups.append((group, None))

    print(f"{M}[!] {G}🛑 Inactive groups ({C}≥ {inactive_days} days or no messages{G}) :")
    for g, date in inactive_groups:
        date_str = date.strftime('%Y-%m-%d %H:%M') if date else "No messages"
        print(f"       {C}• {G}{g.name} {C}→ {G}{date_str}")

    print(f"\n{M}[!] {G}✅ Active groups ({C}< {inactive_days} days{G}) :")
    for g, date in active_groups:
        print(f"       {C}• {G}{g.name} {C}→ {G}{date.strftime('%Y-%m-%d %H:%M')}")

    print(f"\n{M}[!] {G}🔍 Searching for keywords in active groups : {C}" + ", ".join(keywords))
    for g, _ in active_groups:
        print(f"{M}[*] {G}📂 Scanning {C}{g.name}...")
        try:
            async for message in client.iter_messages(g.entity, limit=max_messages):
                if message.date < message_threshold:
                    break  # stop scanning messages older than threshold
                if message.text:
                    if any(keyword.lower() in message.text.lower() for keyword in keywords):
                        highlighted = message.text
                        for kw in keywords:
                            highlighted = re.sub(f"(?i)({re.escape(kw)})", f"{R}\\1{G}", highlighted)
                        print(f"{M}[+] {G}📨 {message.date.strftime('%Y-%m-%d %H:%M')}\n{highlighted}\n{C}{'-' * 50}")

                        if g.name not in keyword_hits:
                            keyword_hits[g.name] = []
                        keyword_hits[g.name].append({
                            "date": message.date.strftime('%Y-%m-%d %H:%M'),
                            "text": message.text
                        })
        except Exception as e:
            print(f"{M}[!] {R}Error reading messages from {g.name} : {e}")

    generate_telegram_html_report(active_groups, inactive_groups, keyword_hits, keywords, inactive_days, message_days, max_messages)
    await client.disconnect()


############ Typosquatting ############
def format_list(value):
    # Format list to space-separated string, or !ServFail if empty
    if not value:
        return "!ServFail"
    return " ".join(value)

def decode_domain(domain):
    try:
        # punycode --> unicode
        if domain.startswith("xn--"):
            return domain.encode("ascii").decode("idna")
        return domain
    except Exception:
        return domain


def typosquatting_registred(target):
    results = dnstwist.run(domain=target, registered=True, format="null")
    print(f"\n{M}[!] {G}🔍 Typosquatted domains registred")
    for entry in results:
        domain_type = entry.get("fuzzer", "unknown").ljust(13)
        domain_name_raw = entry.get("domain", "-")
        domain_name = decode_domain(domain_name_raw).ljust(20)
        ip_addresses = format_list(entry.get("dns_a", []))
        ns_records = format_list(entry.get("dns_ns", []))
        mx_records = format_list(entry.get("dns_mx", []))

        print(f"{M}[*] {C}{domain_type} {G}{domain_name} {R}{ip_addresses} {G}NS:{ns_records} MX:{mx_records}")


def typosquatting_unregistred(target):
    results = dnstwist.run(domain=target, registered=False, format="null")
    print(f"\n{M}[!] {G}🔍 Typosquatted domains unregistred")
    for entry in results:
        if not entry.get("dns_a"):  
            domain_type = entry.get("fuzzer", "unknown").ljust(15)
            domain_name = decode_domain(entry.get("domain", "-")).ljust(20)
            print(f"{M}[*] {C}{domain_type}{G}{domain_name}-")


############ Whois ############
def whoisit(target):
    w = whois.whois(target)
    print(f"\n{M}[!] {G}🔍 Whois search")
    for key, value in w.items():
        print(f"{M}[*] {G}{key} : {Y}{value}")


############ Leak DB ############
BASE_URL = "https://www.ransomlook.io/api/leaks/leaks"

def get_all_leaks():
    resp = requests.get(BASE_URL)
    resp.raise_for_status()
    return resp.json()

def get_leak_details(leak_id):
    url = f"{BASE_URL}/{leak_id}"
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()

def search_leak_by_domain(domain):
    leaks = get_all_leaks()
    for leak in leaks:
        if leak["name"].lower() == domain.lower():
            return leak
    return None


############ Last ransomwares infos/leaks ############
def fetch_recent_posts(number=100):
    url = f"https://www.ransomlook.io/api/recent/{number}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch data: {response.status_code} - {response.text}")


def filter_posts_by_keywords(posts, keywords):
    if not keywords:
        return posts  # No filtering needed
    filtered = []
    for post in posts:
        text = f"{post.get('post_title', '')} {post.get('description', '')}".lower()
        if any(keyword.lower() in text for keyword in keywords):
            filtered.append(post)
    return filtered


def highlight_keywords(text, keywords):
    """Highlight keywords in red in the given text"""
    for kw in keywords:
        if kw:
            text = text.replace(kw, f"{R}{kw}{G}")
            text = text.replace(kw.lower(), f"{R}{kw.lower()}{G}")
            text = text.replace(kw.upper(), f"{R}{kw.upper()}{G}")
            text = text.replace(kw.capitalize(), f"{R}{kw.capitalize()}{G}")
    return text


def display_posts(posts, keywords):
    for post in posts:
        title = highlight_keywords(post["post_title"], keywords)
        desc = highlight_keywords(post["description"], keywords)

        print(f"{M}[+] {C}Title       :{G}", title)
        print(f"    {C}Discovered  :{G}", post["discovered"])
        print(f"    {C}Group       :{G}", post["group_name"])
        print(f"    {C}Link        :{G}", post["link"] or "N/A")
        print(f"    {C}Screenshot  :{G}", post["screen"] or "N/A")
        print(f" {C}→ {G}", desc)
        print(f"{C}-" * 50)


def load_keywords_from_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


############ Ransomwares groups infos ############
def get_ransomwares_groups():
    url = "https://www.ransomlook.io/api/groups"
    response = requests.get(url)
    print(f"\n{M}[!] {G}🔍 Known ransomware groups")

    if response.status_code == 200:
        groups = sorted(response.json())
        for i, name in enumerate(groups, 1):
            print(f" {C}{i:2}. {G}{name}")
            
        target = input(f"\n{G}🔎 Want details about a specific group? (type its name or press [Enter] to skip): ").strip()
        if target:
            # Match insensitive (best UX)
            match = next((g for g in groups if g.lower() == target.lower()), None)

            if match:
                group_url = f"https://www.ransomlook.io/api/group/{match}"
                response = requests.get(group_url)

                if response.status_code == 200:
                    data = response.json()
                    if data and isinstance(data, list) and "locations" in data[0]:
                        print(f"{G}🔗 Links for group : {C}{match}{G}")
                        for loc in data[0]["locations"]:
                            fqdn = loc.get("fqdn", "N/A")
                            title = loc.get("title", "No title")
                            available = loc.get("available", False)
                            updated = loc.get("updated", "")
                            status_icon = "🟢" if available else "🔴"
                            title_str = f" {G}— {title}" if title else ""
                            update_str =  updated if updated else "N/A"
                            
                            print(f"   {status_icon} {C}{fqdn}{title_str}\n    {C}→ {G}Last checked : {update_str}")
                    else:
                        print(f"{R}⚠️ No location data found for this group.")
                else:
                    print(f"{M}[!] {R}Error retrieving group info: {response.status_code}")
            else:
                print(f"{M}[!] {R}Group '{target}' not found in the list.")
    else:
        print(f"{M}[!] {R}Error retrieving group list: {response.status_code}")



############ Launch ############
def main():
    print(banner)
    print(f"{M}[!] {G}🔍 What search would you like to perform ?")
    print(f" {C}1. {G}Telegram & Twitter intelligence gathering")
    print(f" {C}2. {G}Typosquatting")
    print(f" {C}3. {G}Whois info's")
    print(f" {C}4. {G}Leaks info's")
    print(f" {C}5. {G}Recent ransomwares posts")
    print(f" {C}6. {G}List of ransomwares groups (links, ...)")

    choice = input(f" {G}Select (1 to 6) : ").strip()

    if choice == "1":
        keywords = get_keywords()
        if not keywords:
            print(f"{M}[!] {R}No keywords loaded. Closing...")
            exit()

        # Default 10 days
        inactive_days = get_threshold_days()
        message_days = get_message_days()
        max_messages = get_max_messages()

        active_threshold = datetime.now(timezone.utc) - timedelta(days=inactive_days)
        message_threshold = datetime.now(timezone.utc) - timedelta(days=message_days)

        with client:
            client.loop.run_until_complete(
                telegram(keywords, inactive_days, message_days, active_threshold, message_threshold, max_messages)
            )

    elif choice == "2":
        print(f"\n{M}[!] {G}🔍 Type of typosquatting search")
        print(f" {C}1. {G}Generate typosquatted variants")
        print(f" {C}2. {G}Check which typosquatted domains exist")
        sub_choice = input(f" {G}Select (1 or 2) : ").strip()

        target = input(f" {G}Target domain : ").strip()

        if sub_choice == "1":
            typosquatting_unregistred(target)

        elif sub_choice == "2":
            typosquatting_registred(target)

        else:    
            print(f"{M}[!] {R}Invalid choice. Closing...")
            exit()

    elif choice == "3":
        target = input(f" {G}Target domain : ").strip()
        whoisit(target)

    elif choice == "4":
        target = input(f" {G}Target domain : ").strip()
        leak = search_leak_by_domain(target)

        if leak:
            print(f"\n{M}[!] {G}Leak found : {C}{leak['name']} (ID: {leak['id']})")
            details = get_leak_details(leak["id"])
            print(f"{M}[?] {G}Leak details")
            print(f"    {C}- {G}Size     : {details.get('size')}")
            print(f"    {C}- {G}Records  : {details.get('records')}")
            print(f"    {C}- {G}Columns  : {details.get('columns')}")
            print(f"    {C}- {G}Indexed  : {details.get('indexed')}")
            print(f"    {C}- {G}Metadata : {details.get('meta')}")
            print(f"    {C}- {G}Location : {details.get('location')}")
        else:
            print(f"{M}[!] {R}No leaks found for '{target}'.")

    elif choice == "5":
        try:
            print(f"\n{M}[!] {G}🔍 Recent ransomwares posts")
            num_posts = int(input(" How many recent ransomware posts do you want to retrieve? (e.g., 50): "))
            keywords_input = input(r" Keywords to filter (comma-separated), file location (C:\keywords.txt) or nothing to display all posts : ").strip()
            
            # Determine keyword source
            keywords = []
            whatkey = ""
            if keywords_input:
                if ',' not in keywords_input and os.path.isfile(keywords_input):
                    whatkey = f"ransomwares posts displayed with keywords loaded from file {C}{keywords_input}"
                    keywords = load_keywords_from_file(keywords_input)
                else:
                    whatkey = f"ransomwares posts displayed with keyword(s) : {C}{keywords_input}"
                    keywords = [kw.strip() for kw in keywords_input.split(',') if kw.strip()]
            else:
                whatkey = "ransomwares posts displayed"
                
            print(f"{M}[*] {G}{num_posts} {whatkey}")
            posts = fetch_recent_posts(num_posts)
            filtered_posts = filter_posts_by_keywords(posts, keywords)

            print(f"{M}[!] {G}Found {C}{len(filtered_posts)} {G}post(s) matching your criteria")
            display_posts(filtered_posts, keywords)

        except Exception as e:
            print(f"{M}[!] {R}Error :", e)
          
    elif choice == "6":
        get_ransomwares_groups()
    
    
    
    else:    
        print(f"{M}[!] {R}Invalid choice. Closing...")
        exit()


if __name__ == "__main__":
    main()
