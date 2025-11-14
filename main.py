import json
import requests
import random
import string
import time
import urllib.parse


def load_config():
    """加载配置文件"""
    with open('config.json', 'r', encoding='utf-8') as f:
        return json.load(f)


def get_temp_email(config):
    """获取临时邮箱地址"""
    email_base = config['email_base']
    api_url = f"{email_base}/api/generate-email"
    
    headers = {
        'Referer': f"{email_base}/"
    }
    
    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if 'email' in data:
            email = data['email']
            print(f"成功获取临时邮箱: {email}")
            return email
        else:
            print("响应中未找到email字段")
            return None
            
    except requests.RequestException as e:
        print(f"请求失败: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON解析失败: {e}")
        return None


def generate_name():
    """随机生成人名"""
    first_names = ["James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Thomas", "Charles",
                   "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
                  "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"


def generate_password():
    """随机生成密码（10-14位，包含大小写字母、数字、特殊字符，特殊字符占比更多）"""
    length = random.randint(10, 14)
    special_chars = ")*+,-./:;<=>?@[\]^_`{|}"
    
    # 确保密码包含足够的特殊字符（2-4个）
    num_special = random.randint(4, 6)
    num_upper = random.randint(2, 3)
    num_lower = random.randint(2, 3)
    num_digit = random.randint(2, 3)
    
    # 剩余长度随机分配
    remaining = length - (num_special + num_upper + num_lower + num_digit)
    
    # 生成各类字符
    password_chars = []
    password_chars.extend(random.choices(special_chars, k=num_special))
    password_chars.extend(random.choices(string.ascii_uppercase, k=num_upper))
    password_chars.extend(random.choices(string.ascii_lowercase, k=num_lower))
    password_chars.extend(random.choices(string.digits, k=num_digit))
    
    # 填充剩余长度
    if remaining > 0:
        all_chars = string.ascii_letters + string.digits + special_chars
        password_chars.extend(random.choices(all_chars, k=remaining))
    
    # 打乱顺序
    random.shuffle(password_chars)
    
    return ''.join(password_chars)


def signup_account(config, email, referral_code, max_retries=5):
    """注册账号，带重试机制"""
    signup_url = "https://megallm.io/api/auth/signup"
    
    name = generate_name()
    password = generate_password()
    
    payload = {
        "name": name,
        "email": email,
        "password": password,
        "referralCode": referral_code
    }
    
    print(f"\n注册信息:")
    print(f"  姓名: {name}")
    print(f"  邮箱: {email}")
    print(f"  密码: {password}")
    print(f"  邀请码: {referral_code}")
    
    retry_count = 0
    while retry_count < max_retries:
        try:
            print(f"\n发起注册请求... (尝试 {retry_count + 1}/{max_retries})")
            response = requests.post(signup_url, json=payload)
            
            print(f"响应状态码: {response.status_code}")
            
            # 检查状态码是否为200
            if response.status_code == 200:
                data = response.json()
                print(f"响应内容: {data}")
                
                # 检查message字段
                if data.get('message') == "Verification code sent! Please check your email and verify within 10 minutes.":
                    print("\n✓ 注册成功! 验证码已发送到邮箱")
                    return {
                        "email": email,
                        "password": password,
                        "name": name,
                        "success": True
                    }
                else:
                    print(f"\n✗ 响应message不匹配: {data.get('message')}")
            else:
                print(f"\n✗ 状态码非200: {response.status_code}")
                print(f"响应内容: {response.text}")
            
            # 如果不是最后一次重试，等待1分钟后重试
            retry_count += 1
            if retry_count < max_retries:
                print(f"\n等待30秒后重试...")
                time.sleep(30)
            
        except requests.RequestException as e:
            print(f"\n请求异常: {e}")
            retry_count += 1
            if retry_count < max_retries:
                print(f"\n等待30秒后重试...")
                time.sleep(30)
        except json.JSONDecodeError as e:
            print(f"\nJSON解析失败: {e}")
            retry_count += 1
            if retry_count < max_retries:
                print(f"\n等待30秒后重试...")
                time.sleep(30)
    
    print(f"\n✗ 注册失败: 已达到最大重试次数 ({max_retries})")
    return {
        "email": email,
        "password": password,
        "name": name,
        "success": False
    }


def poll_emails(config, email, timeout=600, poll_interval=5):
    """轮询邮箱获取邮件列表"""
    email_base = config['email_base']
    # URL编码邮箱地址，将@替换为%40
    encoded_email = urllib.parse.quote(email)
    api_url = f"{email_base}/api/emails?email={encoded_email}"
    
    headers = {
        'Referer': f"{email_base}/"
    }
    
    print(f"\n开始轮询邮箱，超时时间: {timeout}秒")
    print(f"轮询间隔: {poll_interval}秒")
    
    start_time = time.time()
    attempt = 0
    
    while time.time() - start_time < timeout:
        attempt += 1
        try:
            print(f"\n[尝试 {attempt}] 检查邮件...")
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            # 检查count字段是否为1，表示收到邮件
            if data.get('count') == 1:
                print(f"✓ 收到邮件 (count={data.get('count')})")
                return data.get('emails', [])
            else:
                print(f"暂无邮件 (count={data.get('count', 0)})，等待 {poll_interval} 秒后重试...")
                time.sleep(poll_interval)
                
        except requests.RequestException as e:
            print(f"请求失败: {e}")
            time.sleep(poll_interval)
        except json.JSONDecodeError as e:
            print(f"JSON解析失败: {e}")
            time.sleep(poll_interval)
    
    print(f"\n✗ 轮询超时，未收到邮件")
    return None


def extract_verification_code(emails):
    """从邮件列表中提取验证码"""
    if not emails:
        return None
    
    import re
    
    # 通常验证码在最新的邮件中
    for email in emails:
        print(f"\n检查邮件:")
        print(f"  发件人: {email.get('from_address', 'N/A')}")
        print(f"  主题: {email.get('subject', 'N/A')}")
        print(f"  时间: {email.get('created_at', 'N/A')}")
        
        # 从content字段获取邮件内容
        content = email.get('content', '')
        
        if content:
            # 尝试提取验证码（通常是6位数字）
            # 根据示例，验证码格式为独立的6位数字
            patterns = [
                r'Your Verification Code\s+(\d{6})',  # 匹配"Your Verification Code"后的6位数字
                r'验证码[：:]\s*(\d{4,8})',  # 中文格式
                r'verification code[：:]\s*(\d{4,8})',  # 英文格式
                r'\b(\d{6})\b',  # 6位数字
            ]
            
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    code = match.group(1)
                    print(f"\n✓ 找到验证码: {code}")
                    return code
    
    print(f"\n✗ 未能从邮件中提取验证码")
    return None


def verify_email(config, email, otp):
    """验证邮箱"""
    verify_url = "https://megallm.io/api/auth/verify"
    
    payload = {
        "email": email,
        "otp": otp
    }
    
    print(f"\n发起验证请求...")
    print(f"  邮箱: {email}")
    print(f"  验证码: {otp}")
    
    try:
        response = requests.post(verify_url, json=payload)
        
        print(f"\n响应状态码: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"响应内容: {data}")
            
            # 检查verified字段
            if data.get('verified') == True:
                print("\n✓ 邮箱验证成功!")
                return {
                    "success": True,
                    "userId": data.get('userId'),
                    "apiKey": data.get('apiKey'),
                    "message": data.get('message')
                }
            else:
                print(f"\n✗ 验证失败: verified={data.get('verified')}")
                return {"success": False}
        else:
            print(f"\n✗ 验证失败: 状态码{response.status_code}")
            print(f"响应内容: {response.text}")
            return {"success": False}
            
    except requests.RequestException as e:
        print(f"\n验证请求异常: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"错误详情: {e.response.text}")
        return {"success": False}
    except json.JSONDecodeError as e:
        print(f"\nJSON解析失败: {e}")
        return {"success": False}


def login_and_get_session(email, password):
    """登录并获取session token"""
    try:
        # 使用session来保持cookie
        session = requests.Session()
        
        # 步骤0: 访问session接口获取初始cookies
        print(f"\n访问session接口...")
        session_response = session.get("https://megallm.io/api/auth/session")
        print(f"✓ Session接口响应: {session_response.status_code}")
        
        # 步骤1: 获取CSRF token
        print(f"\n获取CSRF token...")
        csrf_response = session.get("https://megallm.io/api/auth/csrf")
        csrf_data = csrf_response.json()
        csrf_token = csrf_data.get('csrfToken')
        
        if not csrf_token:
            print("✗ 未能获取CSRF token")
            return None
        
        print(f"✓ CSRF token: {csrf_token[:20]}...")
        
        # 步骤2: 登录获取session token
        print(f"\n发起登录请求...")
        login_data = {
            'email': email,
            'password': password,
            'redirect': 'false',
            'csrfToken': csrf_token,
            'callbackUrl': 'https://megallm.io/auth/signin',
            'json': 'true'
        }
        
        # 使用session发送请求，自动携带所有cookies
        login_response = session.post(
            "https://megallm.io/api/auth/callback/credentials",
            data=login_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        print(f"登录响应状态码: {login_response.status_code}")
        print(f"登录响应内容: {login_response.text[:200]}...")
        
        # 从cookies中提取session token
        session_token = session.cookies.get('__Secure-next-auth.session-token')
        
        if session_token:
            print(f"✓ 成功获取session token")
            return session_token
        else:
            print(f"✗ 未能获取session token")
            print(f"所有cookies: {list(session.cookies.keys())}")
            return None
            
    except Exception as e:
        print(f"✗ 登录异常: {e}")
        import traceback
        traceback.print_exc()
        return None


def get_referral_stats(session_token):
    """获取推荐统计信息"""
    try:
        print(f"\n获取推荐统计...")
        cookies = {'__Secure-next-auth.session-token': session_token}
        
        response = requests.get(
            "https://megallm.io/api/referral/stats",
            cookies=cookies
        )
        
        if response.status_code == 200:
            data = response.json()
            referral_code = data.get('referralCode')
            total_referred = data.get('stats', {}).get('totalReferred', 0)
            
            print(f"✓ 推荐码: {referral_code}")
            print(f"  总推荐人数: {total_referred}")
            
            return referral_code
        else:
            print(f"✗ 获取推荐统计失败: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"✗ 获取推荐统计异常: {e}")
        return None


def save_to_csv(email, password, api_key, csv_file='accounts.csv'):
    """保存账号信息到CSV文件"""
    import csv
    import os
    
    # 检查文件是否存在，如果不存在则创建并写入表头
    file_exists = os.path.isfile(csv_file)
    
    with open(csv_file, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # 如果文件不存在，先写入表头
        if not file_exists:
            writer.writerow(['Email', 'Password', 'API Key', 'Created At'])
        
        # 写入账号信息
        from datetime import datetime
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        writer.writerow([email, password, api_key, created_at])
    
    print(f"\n✓ 账号信息已保存到 {csv_file}")


# 全局邀请码池
REFERRAL_CODE_POOL = []
REFERRAL_POOL_FILE = 'referral_pool.json'


def load_referral_pool():
    """从本地文件加载邀请码池"""
    global REFERRAL_CODE_POOL
    import os
    
    if os.path.exists(REFERRAL_POOL_FILE):
        try:
            with open(REFERRAL_POOL_FILE, 'r', encoding='utf-8') as f:
                REFERRAL_CODE_POOL = json.load(f)
            print(f"✓ 已从本地加载 {len(REFERRAL_CODE_POOL)} 个邀请码")
        except Exception as e:
            print(f"⚠ 加载邀请码池失败: {e}")
            REFERRAL_CODE_POOL = []
    else:
        print("本地无邀请码池文件，将使用配置中的默认邀请码")
        REFERRAL_CODE_POOL = []


def save_referral_pool():
    """将邀请码池保存到本地文件"""
    global REFERRAL_CODE_POOL
    try:
        with open(REFERRAL_POOL_FILE, 'w', encoding='utf-8') as f:
            json.dump(REFERRAL_CODE_POOL, f, ensure_ascii=False, indent=2)
        print(f"✓ 邀请码池已保存到本地文件")
    except Exception as e:
        print(f"⚠ 保存邀请码池失败: {e}")


def update_referral_pool(new_code):
    """更新邀请码池并保存到本地"""
    global REFERRAL_CODE_POOL
    if new_code and new_code not in REFERRAL_CODE_POOL:
        REFERRAL_CODE_POOL.append(new_code)
        print(f"\n✓ 邀请码池已更新，当前包含 {len(REFERRAL_CODE_POOL)} 个邀请码")
        save_referral_pool()


def get_random_referral_code(config):
    """从池中随机获取邀请码，如果池为空则使用配置中的"""
    global REFERRAL_CODE_POOL
    if REFERRAL_CODE_POOL:
        code = random.choice(REFERRAL_CODE_POOL)
        print(f"使用邀请码池中的邀请码: {code}")
        return code
    else:
        code = config.get('referral_code', '')
        print(f"使用配置中的默认邀请码: {code}")
        return code


def register_once(config):
    """执行一次完整的注册流程"""
    print("\n" + "="*60)
    print("开始新的注册流程")
    print("="*60)
    
    # 步骤1: 获取邀请码
    print("\n[步骤1] 获取邀请码...")
    referral_code = get_random_referral_code(config)
    
    # 步骤2: 获取临时邮箱
    print("\n[步骤2] 获取临时邮箱...")
    email = get_temp_email(config)
    
    if not email:
        print("✗ 获取邮箱失败")
        return False
    
    # 步骤3: 注册账号
    print("\n[步骤3] 注册账号...")
    account_info = signup_account(config, email, referral_code)
    
    if not account_info['success']:
        print("\n✗ 注册失败")
        return False
    
    # 步骤4: 轮询邮箱获取验证码
    print("\n[步骤4] 轮询邮箱获取验证码...")
    emails = poll_emails(config, email, timeout=600, poll_interval=5)
    
    if not emails:
        print("\n✗ 未收到验证邮件")
        return False
    
    # 步骤5: 提取验证码
    print("\n[步骤5] 提取验证码...")
    verification_code = extract_verification_code(emails)
    
    if not verification_code:
        print("\n✗ 未能提取验证码")
        return False
    
    # 步骤6: 验证邮箱
    print("\n[步骤6] 验证邮箱...")
    verify_result = verify_email(config, email, verification_code)
    
    if not verify_result['success']:
        print("\n✗ 邮箱验证失败")
        return False
    
    # 步骤7: 保存账号信息
    print("\n[步骤7] 保存账号信息...")
    save_to_csv(email, account_info['password'], verify_result['apiKey'])
    
    # 步骤8: 登录获取session token并更新邀请码池
    print("\n[步骤8] 登录获取推荐码...")
    session_token = login_and_get_session(email, account_info['password'])
    
    if session_token:
        new_referral_code = get_referral_stats(session_token)
        if new_referral_code:
            update_referral_pool(new_referral_code)
    else:
        print("⚠ 未能获取session token，跳过邀请码池更新")
    
    print("\n" + "="*60)
    print("✓ 注册流程成功完成!")
    print(f"  邮箱: {email}")
    print(f"  密码: {account_info['password']}")
    print(f"  API Key: {verify_result['apiKey']}")
    print("="*60)
    
    return True


def main():
    print("="*60)
    print("自动注册机启动")
    print("="*60)
    
    # 加载配置
    config = load_config()
    
    # 加载本地邀请码池
    print("\n加载邀请码池...")
    load_referral_pool()
    
    success_count = 0
    fail_count = 0
    
    # 循环注册
    while True:
        try:
            result = register_once(config)
            
            if result:
                success_count += 1
                print(f"\n当前统计: 成功 {success_count} 次, 失败 {fail_count} 次")
            else:
                fail_count += 1
                print(f"\n当前统计: 成功 {success_count} 次, 失败 {fail_count} 次")
                print("等待30秒后重试...")
                time.sleep(30)
            
            # 成功后短暂等待，避免请求过快
            if result:
                print("\n等待30秒后进行下一次注册...")
                time.sleep(30)
                
        except KeyboardInterrupt:
            print("\n\n用户中断，程序退出")
            print(f"最终统计: 成功 {success_count} 次, 失败 {fail_count} 次")
            break
        except Exception as e:
            fail_count += 1
            print(f"\n✗ 发生异常: {e}")
            print("等待30秒后重试...")
            time.sleep(30)


if __name__ == "__main__":
    main()
