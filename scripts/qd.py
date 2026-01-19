import requests
import json
import sys
import os

def send_signin_request():
    # 适配 Windows 控制台中文输出
    if sys.platform == "win32":
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    
    # 接口地址
    url = "https://gzpengru.weimbo.com/api/index.php?ackey=GZYTAPPLET"
    Token = os.environ.get("3rdsession", "")
    headers = {
        "3rdSession": Token,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "Host": "gzpengru.weimbo.com",
        "Referer": "https://servicewechat.com/wxc86c9aecdb67f876/10/page-frame.html",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090c39)XWEB/14315",
        "xweb_xhr": "1"
    }
    
    data = {
        "action": "userQiandao"
    }
    
    try:
        response = requests.post(
            url=url,
            headers=headers,
            json=data,
            timeout=10,
            verify=False
        )
        
        # 强制指定编码为 UTF-8
        response.encoding = "utf-8"
        raw_response = response.text
        
        # 打印处理后的响应内容（显示中文）
        decoded_response = json.dumps(json.loads(raw_response), ensure_ascii=False)
        
        # 解析为字典并提取关键数值
        try:
            response_json = json.loads(raw_response)
            
            
            # ========== 核心：提取 add_jf（1400） ==========
            print(f"\n=== 关键数值提取 ===")
            # 先判断 Data 字段是否是字典（签到成功时返回字典，失败时返回字符串）
            if isinstance(response_json.get('Data'), dict):
                add_jf = response_json['Data'].get('add_jf', '未获取到加分值')
                user_jf = response_json['Data'].get('user_jf', '未获取到总积分')
                if_qiand = response_json['Data'].get('if_qiand', '未知')
                print(f"本次签到加分: {add_jf}")       # 提取 1400
                print(f"当前总积分: {user_jf}")         # 提取 15600
                print(f"是否签到成功: {if_qiand}")      # 提取 True/False
            else:
                # 签到失败时（如冷却中），显示提示信息
                print(f"签到提示: {response_json['Data']}")
                
        except json.JSONDecodeError as e:
            print(f"JSON 解析失败: {e}")
            
    except requests.exceptions.RequestException as e:
        print(f"请求失败: {e}")

if __name__ == "__main__":
    # 关闭 SSL 警告
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    send_signin_request()