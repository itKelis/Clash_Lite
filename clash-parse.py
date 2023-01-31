import yaml
import requests
import base64
import json
import re
import os
import urllib
import logging


def getsub(links):
    res = gethtml(links)
    try:
        clash = decodeToConfDict(res.text)
        return clash
    except Exception:
        logging.warning('获取订阅失败，请检查网络')
        return None

def subconvert(clash):

    final = generateProxies(clash)
    if final is not None:
        with open('config1.yaml','w', encoding='utf-8') as d:
            yaml.dump(final, d, sort_keys=False, allow_unicode=True)

def gethtml(url):
    try:
        i = 1
        while i < 10:
            html = requests.get(url)
            if html is not None :
                return html
            else:
                i+=1
    except requests.exceptions.RequestException:
        logging.warning("获取失败的订阅：{}".format(url))
        input("继续")
        return None

def decodeToConfDict(message_string):

    message_string += "=" * (4 - len(message_string) % 4)
    result = base64.b64decode(message_string.encode('utf8')).decode('utf8').splitlines()
    proxies = []

    for proxy in result:

        if proxy.startswith("vmess://"):
            conf_string = proxy[8:]
            decoded_conf_string = base64.b64decode(conf_string.encode('utf8')).decode('utf8')
            decoded_conf_object = json.loads(decoded_conf_string)
            proxies.append(vmess2clash(decoded_conf_object))
        
        if proxy.startswith("trojan://"):
            proxies.append(trojan2clash(proxy))

        if proxy.startswith("ss://"):
            proxies.append(ss2clash(proxy))

    return proxies


def ss2clash(d):
    """
    将ss订阅结果转换成clash的proxy格式
    :param d:

    :return: new_d
    """
    a = re.match("ss://(.*)@(.*):(.*)#(.*)",d).groups()
    b64 = a[0]
    if len(b64) % 3 != 0:
        b64 += (len(b64) % 3) * "="
    params = base64.b64decode(b64).decode("utf-8").split(":")

    new_d = {
        "name" : urllib.parse.unquote(a[-1]),
        "type" : "ss",
        "server" : a[1],
        "port" : a[2],
        "password" : params[1],
        "cipher" : str(params[0]),
        "udp": True
    }

    return new_d

def trojan2clash(d):
    """
    将trojan订阅结果转换成clash的proxy格式
    :param d:

    :return: new_d
    """
    a=re.match('trojan://([^@]+)@([^:]+):([0-9]+)\\?([^#]+)#(.*)',d)
    a = a.groups()
    params={str.split('=')[0]:str.split('=')[1] for str in a[-2].split('&')}

    new_d = {
        "name" : urllib.parse.unquote(a[-1]),
        "type" : "trojan",
        "server" : a[1],
        "port" : int(a[2]),
        "password" : a[0],
        "udp" : True,
    }

    params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(d).query))
    
    if "allowInsecure" in params.keys():
        new_d["skip-cert-verify"] = False
    if "sni" in params.keys():
        new_d["sni"] = params['sni']
    
    return new_d


def vmess2clash(d):
    """
    将vmess订阅结果转换成clash的proxy格式
    :param d:

    :return: new_d
    """
    new_d = {
        "name": d["ps"],
        "type": "vmess",
        "server": d["add"],
        "port": int(d["port"]),
        "uuid": d["id"],
        "alterId": 0,
        "cipher": "auto",
        "udp": True,
        "network": d["net"],
        'tls': True if d['tls'] == 'tls' else False,

    }

    if d["net"] == 'ws':

        new_d['ws-opts'] = {
            'path': '/' if d['path'] is None else d['path'],
            'headers': {"Host": d['add'] if d['host'] is None else d['host']} 
        }

    logging.debug(d)
    
    return new_d

def generateProxies(proxies):
    names = [p['name'] for p in proxies]

    ExcludeLists = ('🐟 漏网之鱼','🛑 广告拦截','PROXY','bilibili')

    with open('local.yaml') as f:
        try:
            localParse = yaml.load(f.read(), Loader= yaml.FullLoader)
        except Exception:
            localParse = None

    parse = gethtml(r'https://raw.githubusercontent.com/itKelis/Clash_Lite/main/clash-parse.yaml')
    if parse:
        result = yaml.load(parse.text , Loader = yaml.FullLoader)

        if localParse:
            result['dns'] = localParse['dns']
            result['tun'] = localParse['tun']

        result['proxies'] = proxies
        
        for i in range(len(result['proxy-groups'])):
            
            if result['proxy-groups'][i]['name'] not in ExcludeLists:
                result['proxy-groups'][i]['proxies'] +=names

                if result['proxy-groups'][i]['name'] == '🔄 自动测速':
                    result['proxy-groups'][i]['proxies'].remove('DIRECT')

        countries = country(names)
        fullproxy = [i['name'] for i in countries] + result['proxy-groups'][0]['proxies']
        result['proxy-groups'].extend(countries)
        result['proxy-groups'][0]['proxies'] = fullproxy
        result['proxy-groups'][3]['proxies'].insert(0,'0.1倍节点')
        return result
    else:
        return None

def country(proxieName):
    loclist = ('🇯🇵 日本',  '🇭🇰 香港', '🇺🇸 美国', '🇸🇬 狮城', '🇰🇷 首尔', '🇹🇼 台湾', '🇪🇺 欧洲',  '0.1倍节点')

    grouplist = {
    "jplist" : ('东京', '大阪', 'Japan'),
    "hklist" : ('香港', 'Hong Kong'),
    "uslist" : ('圣荷西', '美西', 'USA'),
    "sglist" : ('狮城', 'Singapore'),
    "krlist" : ('首尔'),
    "twlist" : ('台湾','Taiwan'),
    "urlist" : ('爱尔兰','巴黎','法兰克福','波特兰','伦敦','France'),
    "lownet" : ('x')
    }

    coun = []
    for loc in loclist:
        coun.append(
            {
                'name': loc,
                'type': 'load-balance',
                'interval': 1200,
                'url': 'http://www.google.com/generate_204',
                # 'url': 'http://www.github.com',
                'strategy': 'consistent-hashing',
                'proxies': [],
            }
        )

    keyname = tuple(grouplist.keys())
    for i in proxieName:
        
        for keys in range(len(keyname)):
            if any(str in i for str in grouplist[keyname[keys]]):
                coun[keys]['proxies'].append(i)

    coun = [x for x in coun if len(x['proxies']) != 0]
    return coun

def main():

    logging.basicConfig(level=logging.DEBUG,
    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')

    clashs = []
    with open('local.yaml') as f:
        try:
            subs = yaml.load(f.read(), Loader= yaml.FullLoader)['sub']
        except Exception:
            logging.error('未获取到任何订阅，请检查local.yaml的sub字段')
            # subs = (#r'https://bigairport.date/api/v1/client/subscribe?token=5f46dbe1df26b6fcc0ff193129c39932',
            # 'https://moes.lnaspiring.com/Moe233-Subs/aln/api/v1/client/subscribe?token=857c49b06b064690eca348e827a80dbd',)

    for sub in subs:
        logging.info("现在正在获取：{}".format(sub))
        now = getsub(sub)
        if now is not None:
            clashs.append(now)
        else:
            continue
    if clashs:
        finalProxies = [i for ii in clashs for i in ii]
        subconvert(finalProxies)
    

main()
