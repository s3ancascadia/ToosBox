import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress

# 映射字典，用于将各种模式转换为统一的键
MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix', 
    'HOST-SUFFIX': 'domain_suffix', 
    'DOMAIN': 'domain', 
    'HOST': 'domain', 
    'host': 'domain',
    'DOMAIN-KEYWORD':'domain_keyword', 
    'HOST-KEYWORD': 'domain_keyword', 
    'host-keyword': 'domain_keyword', 
    'IP-CIDR': 'ip_cidr',
    'ip-cidr': 'ip_cidr', 
    'IP-CIDR6': 'ip_cidr', 
    'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr', 
    'GEOIP': 'geoip', 
    'DST-PORT': 'port',
    'SRC-PORT': 'source_port', 
    "URL-REGEX": "domain_regex", 
    "DOMAIN-REGEX": "domain_regex"
}

# 从URL读取YAML文件
def read_yaml_from_url(url):
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    yaml_data = yaml.safe_load(response.text)  # 解析YAML数据
    return yaml_data

# 从URL读取列表并处理为DataFrame
def read_list_from_url(url):
    df = pd.read_csv(url, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'])
    filtered_rows = []
    rules = []

    # 处理包含AND逻辑规则的行
    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {
                "type": "logical",
                "mode": "and",
                "rules": []
            }
            pattern = ",".join(row.values.astype(str))
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                for keyword in MAP_DICT.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({MAP_DICT[keyword]: value})
            rules.append(rule)

    # 过滤掉包含AND的行，并将其余行保存在filtered_rows中
    for _, row in df.iterrows():
        if 'AND' not in row['pattern']:
            filtered_rows.append(row)
    
    # 转换为DataFrame
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules

# 判断地址是否为IPv4或IPv6
def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

# 解析链接并将其转换为DataFrame
def parse_and_convert_to_dataframe(link):
    rules = []
    # 根据链接扩展名处理不同类型的文件
    if link.endswith('.yaml') or link.endswith('.txt'):
        try:
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                line_content = lines[0]
                items = line_content.split()
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address.lstrip('+.')  # 去除开头的"+"或"."
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)
                if pattern == "IP-CIDR" and "no-resolve" in address:
                    address = address.split(',', 1)[0]
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        except:
            df, rules = read_list_from_url(link)
    else:
        df, rules = read_list_from_url(link)
    return df, rules

# 对字典进行递归排序
def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

# 解析链接列表并生成对应的文件
def parse_list_file(link, output_directory):
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(parse_and_convert_to_dataframe, [link]))  # 使用线程池并行处理链接
            dfs = [df for df, _ in results]  # 提取DataFrame内容
            rules_list = [rules for _, rules in results]  # 提取逻辑规则内容
            df = pd.concat(dfs, ignore_index=True)  # 合并为一个DataFrame

        # 过滤无效行并去重
        df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
        df = df.drop_duplicates().reset_index(drop=True)
        df['pattern'] = df['pattern'].replace(MAP_DICT)  # 替换pattern为映射字典中的值

        os.makedirs(output_directory, exist_ok=True)  # 创建输出目录

        result_rules = {"version": 1, "rules": []}
        domain_entries = []

        # 根据模式将地址分类并存储
        for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
            if pattern == 'domain_suffix':
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
            elif pattern == 'domain':
                domain_entries.extend([address.strip() for address in addresses])
            else:
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
        
        # 处理 domain_entries 并去重
        domain_entries = list(set(domain_entries))
        if domain_entries:
            result_rules["rules"].insert(0, {'domain': domain_entries})

        # 如果存在逻辑规则，则将其添加到结果中
        if rules_list and rules_list[0]:
            result_rules["rules"].extend(rules_list[0])

        # 写入JSON文件
        file_name = os.path.join(output_directory, f"{os.path.basename(link).split('.')[0]}.json")
        with open(file_name, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')  # 替换转义字符
            output_file.write(result_rules_str)

        # 编译为.srs文件
        srs_path = file_name.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
        return file_name
    except Exception as e:
        print(f'处理链接 {link} 时出错：{e}')
        pass

# 读取 links.txt 中的每个链接并生成对应的 JSON 文件
with open("../links.txt", 'r') as links_file:
    links = links_file.read().splitlines()

# 过滤掉空行和注释行
links = [l for l in links if l.strip() and not l.strip().startswith("#")]

output_dir = "./"
result_file_names = []

# 处理每个链接并生成文件
for link in links:
    result_file_name = parse_list_file(link, output_directory=output_dir)
    result_file_names.append(result_file_name)

# 打印生成的文件名（可选）
# for file_name in result_file_names:
#     print(file_name)