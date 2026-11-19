#!/usr/bin/env python3
import os
import glob
import yaml

def read_yaml(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def save_file(content, file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content.rstrip() + "\n")

def build_header(title, rel_path, category_desc, policy):
    return (
        f"# {title}\n"
        f"# {rel_path} ({policy.upper()})\n"
        f"# {category_desc}\n"
    )

def parse_rule_line(raw_rule):
    rule_str = raw_rule.split("#")[0].strip()
    if not rule_str:
        return None
    
    parts = [p.strip() for p in rule_str.split(",")]
    if len(parts) < 2:
        return None
    
    method = parts[0].upper()
    content = parts[1]
    
    policy = "proxy"
    if len(parts) >= 3:
        p = parts[2].upper()
        if "REJECT" in p:
            policy = "reject"
        elif "DIRECT" in p:
            policy = "direct"
            
    if method in ["IP-CIDR", "IP-CIDR6", "GEOIP"]:
        clean_rule = f"{method},{content},no-resolve"
    else:
        clean_rule = f"{method},{content}"
        
    return method, content, policy, clean_rule

def classify_rules(rules):
    buckets = {
        "domain_set": {"direct": set(), "reject": set(), "proxy": set()},
        "non_ip": {"direct": set(), "reject": set(), "proxy": set()},
        "ip": {"direct": set(), "reject": set(), "proxy": set()},
        "all": set()
    }

    for raw_rule in rules:
        parsed = parse_rule_line(raw_rule)
        if not parsed:
            continue
        
        method, content, policy, clean_rule = parsed

        if method == "DOMAIN-SUFFIX":
            buckets["domain_set"][policy].add(f".{content}")
        elif method == "DOMAIN":
            buckets["domain_set"][policy].add(content)

        if method in ["IP-CIDR", "IP-CIDR6", "GEOIP"]:
            buckets["ip"][policy].add(clean_rule)
        else:
            buckets["non_ip"][policy].add(clean_rule)

        buckets["all"].add(clean_rule)

    return buckets

def write_rules(title, base_dir, site_key, buckets):
    target_dir = os.path.join(base_dir, site_key) if site_key else base_dir

    dir_map = {
        "domain_set": "domain-set",
        "non_ip": "non-ip",
        "ip": "ip"
    }

    def save_category(category_key, policy, items, desc):
        if not items:
            return
        folder_name = dir_map[category_key]
        rel_path = f"{site_key}/{folder_name}/{policy}.list" if site_key else f"{folder_name}/{policy}.list"
        full_path = os.path.join(target_dir, folder_name, f"{policy}.list")
        
        content = build_header(title, rel_path, desc, policy) + "\n".join(sorted(items))
        save_file(content, full_path)

    for policy in ["reject", "direct", "proxy"]:
        save_category("domain_set", policy, buckets["domain_set"][policy], "DOMAIN-SET")
        save_category("non_ip", policy, buckets["non_ip"][policy], "Non-IP")
        save_category("ip", policy, buckets["ip"][policy], "IP")

    all_ip = sorted(buckets["ip"]["reject"] | buckets["ip"]["direct"] | buckets["ip"]["proxy"])
    if all_ip:
        rel_path = f"{site_key}/ip.list" if site_key else "ip.list"
        content = build_header(title, rel_path, "All IP", "all") + "\n".join(all_ip)
        save_file(content, os.path.join(target_dir, "ip.list"))

    all_rules = sorted(buckets["all"])
    if all_rules:
        rel_path = f"{site_key}/rules.list" if site_key else "rules.list"
        content = build_header(title, rel_path, "All Rules", "all") + "\n".join(all_rules)
        save_file(content, os.path.join(target_dir, "rules.list"))

def process_config(file_path, output_base="generated"):
    data = read_yaml(file_path)
    config = data.get("config", data)
    site_name = config.get("name", os.path.splitext(os.path.basename(file_path))[0])
    display_name = config.get("display_name", site_name)
    rules = config.get("rules", [])
    
    buckets = classify_rules(rules)
    write_rules(display_name, output_base, site_name, buckets)
    return site_name, buckets

def main():
    output_base = "generated"
    rules_dir = "rules"
    
    combined_buckets = {
        "domain_set": {"direct": set(), "reject": set(), "proxy": set()},
        "non_ip": {"direct": set(), "reject": set(), "proxy": set()},
        "ip": {"direct": set(), "reject": set(), "proxy": set()},
        "all": set()
    }

    yaml_files = sorted(glob.glob(os.path.join(rules_dir, "*.yaml")))
    for yf in yaml_files:
        _, buckets = process_config(yf, output_base)
        for cat in ["domain_set", "non_ip", "ip"]:
            for pol in ["direct", "reject", "proxy"]:
                combined_buckets[cat][pol].update(buckets[cat][pol])
        combined_buckets["all"].update(buckets["all"])

    write_rules("anti-ip-attribution", output_base, "", combined_buckets)

if __name__ == "__main__":
    main()
