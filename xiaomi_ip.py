import requests
import hashlib
import json

# 如果你的路由器网关IP不是这个，需改成对应地址
ROUTER_IP = "192.168.1.1"
ADMIN_PASSWORD = "adminpassword"

# 如果无用户名，这里可置空，也可尝试写 'admin' 看自己路由器版本需要

def md5_hash(text):
    """部分小米固件需要对密码进行 MD5。若不需要加密，可直接用明文发送。"""
    return hashlib.md5(text.encode('utf-8')).hexdigest()


def login_and_get_stok():
    """
    登录路由器并获取 stok。返回形如: "xxxxxxx"
    如果需要明文密码，可改请求体。部分固件需要 MD5 后再传。
    """
    url = f"http://{ROUTER_IP}/cgi-bin/luci/api/xqsystem/login"

    # 注意：某些版本要传 username=admin，某些直接 username=''； 
    # 如果需要 MD5，就这样:
    # password_md5 = md5_hash(ADMIN_PASSWORD)
    # data = {"username": "", "password": password_md5}

    # 如果确认可以明文:
    data = {"username": "admin", "password": ADMIN_PASSWORD}

    resp = requests.post(url, data=data, timeout=5)
    resp.raise_for_status()  # 若状态码非200会抛异常

    info = resp.json()
    # 返回JSON结构可能包含 code, msg, token, stok 等字段
    if "token" in info:
        # 某些旧版字段名
        return info["token"]
    elif "stok" in info:
        return info["stok"]
    else:
        raise RuntimeError(f"Login failed or unknown response: {info}")


def get_wan_info(stok):
    """
    登录成功后，用 stok 访问获取 WAN 信息的接口。
    以下以 misystem/status 做示例，不同固件可能路径不同。
    """
    url = f"http://{ROUTER_IP}/cgi-bin/luci/;stok={stok}/api/misystem/status"

    resp = requests.get(url, timeout=5)
    resp.raise_for_status()

    info = resp.json()
    return info

def get_ip_config(stok):
    url = f"http://{ROUTER_IP}/cgi-bin/luci/;stok={stok}/api/xqnetwork/pppoe_status"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()

    info = resp.json()
    return info

def main():
    try:
        stok = login_and_get_stok()
        print("Login success, stok =", stok)

        wan_data = get_wan_info(stok)
        print("WAN info data:", json.dumps(wan_data, indent=2))

        wan_ip_data = get_ip_config(stok)
        print("WAN IP data:", json.dumps(wan_ip_data, indent=2))
        # 你可以根据 WAN 数据结构，从中提取 ip, dns 等关键信息

    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    main()