#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys
import time
import json
import hashlib
import threading
from struct import pack, unpack
from pathlib import Path
from multiprocessing import Process

SECRET_KEY = b"^FStx,wl6NquAVRF@f%6\x00"

serial_num = 0
user_id = 0
session_bytes = bytes()

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

def build_login_token(session, server_id):
    start1 = int.from_bytes(session[3:7], 'big')
    start2 = int.from_bytes(session[10:14], 'big')
    
    fixed_str = "fREd hAo crAzy BAby in Our ProgRAm?"
    s = str(start2) + fixed_str[5:16] + str(start1)
    
    md5_result = md5_hash(s)
    token_str = md5_result[5:22]
    
    token = token_str.encode('ascii')
    
    return token

def get_int(data):
    if isinstance(data, bytes) and len(data) >= 4:
        return int.from_bytes(data[:4], "big")
    return 0

def get_hex(num):
    return f"{num:08X}"



class Packet:
    def __init__(self, data=None):
        if data is None:
            self.length = 0
            self.serial_num = 0
            self.cmd_id = 0
            self.user_id = 0
            self.version = 0
            self.body = bytes()
        else:
            if isinstance(data, str):
                data = bytes.fromhex(data)
            if len(data) >= 17:
                self.length, self.serial_num, self.cmd_id, self.user_id, self.version = unpack("!IBIII", data[:17])
                self.body = data[17:]
            else:
                self.length, self.serial_num, self.cmd_id, self.user_id, self.version = 0, 0, 0, 0, 0
                self.body = bytes()

    def data(self):
        head = pack("!IBIII", self.length, self.serial_num, self.cmd_id, self.user_id, self.version)
        return head + self.body

    def get_serial_num(self):
        global serial_num, user_id
        self.length = len(self.body) + 18
        self.user_id = user_id
        self.version = 0
        if self.cmd_id == 201:
            serial_num = 65
        else:
            crc = 0
            for i in range(len(self.body)):
                crc ^= self.body[i]
            serial_num = (serial_num - int(serial_num / 7) + 147 + (self.length - 1) % 21 + 
                         self.cmd_id % 13 + crc) % 256
        self.serial_num = serial_num

    def encrypt(self):
        self.get_serial_num()
        res = bytearray(len(self.body) + 1)
        key_index = 0
        for index in range(len(self.body)):
            res[index] = self.body[index] ^ SECRET_KEY[key_index % 21]
            key_index += 1
            if key_index == 22:
                key_index = 0
        for index in range(len(res) - 1, 0, -1):
            res[index] |= res[index - 1] >> 3
            res[index - 1] = (res[index - 1] << 5) % 256
        res[0] |= 3
        self.body = res
        return self

    def decrypt(self):
        if len(self.body) == 0:
            return
        res = bytearray(len(self.body) - 1)
        key_index = 0
        for index in range(len(res)):
            res[index] = (self.body[index] >> 5) | (self.body[index + 1] << 3) % 256
            res[index] ^= SECRET_KEY[key_index % 21]
            key_index += 1
            if key_index == 22:
                key_index = 0
        self.body = res


class Client:
    def __init__(self):
        self.login_socket = None
        self.main_socket = None
        self.connected = False
        self.recv_buffer = bytearray()
        self.heartbeat_thread = None
        self.heartbeat_running = False
        self.send_lock = threading.Lock()
    
    def connect_login_server(self):
        try:
            self.login_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.login_socket.settimeout(10)
            self.login_socket.connect(("123.206.131.236", 1863))
            print("[+] Auth server connected")
            return True
        except Exception as e:
            print(f"[-] Auth server failed: {e}")
            return False
    
    def login_server_auth(self, username, password, server_id):
        global user_id, session_bytes
        try:
            pwd_hash = md5_hash(md5_hash(password))
            
            first_packet = bytearray([
                0x00,0x00,0x00,0x93,0x01,0x00,0x00,0x00,0x67
            ])
            first_packet.extend(int(username).to_bytes(4, 'big'))
            first_packet.extend(bytes([0x00,0x00,0x00,0x00]))
            first_packet.extend(pwd_hash.encode('ascii'))
            first_packet.extend(pack("!III", 0, 1, 0))
            first_packet.extend(bytes(22))
            first_packet.extend(bytes(64))
            
            self.login_socket.send(bytes(first_packet))
            
            self.login_socket.settimeout(1.2)
            resp_data = bytearray()
            try:
                while True:
                    chunk = self.login_socket.recv(4096)
                    if not chunk:
                        break
                    resp_data.extend(chunk)
            except socket.timeout:
                pass
            
            if len(resp_data) < 37:
                print("[-] Auth response invalid")
                return False
            
            session_16 = resp_data[21:37]
            verify_packet = bytearray()
            verify_packet.extend(pack("!I", 37))
            verify_packet.append(1)
            verify_packet.extend(pack("!I", 105))
            verify_packet.extend(int(username).to_bytes(4, 'big'))
            verify_packet.extend(pack("!I", 0))
            verify_packet.extend(session_16)
            verify_packet.extend(bytes(4))
            
            self.login_socket.send(bytes(verify_packet))
            server_select_packet = bytearray()
            server_select_packet.extend(pack("!I", 205))
            server_select_packet.append(1)
            server_select_packet.extend(pack("!I", 106))
            server_select_packet.extend(int(username).to_bytes(4, 'big'))
            server_select_packet.extend(pack("!I", 0))
            server_select_packet.extend(pack("!I", server_id))
            server_select_packet.extend(pack("!I", server_id))
            server_select_packet.extend(pack("!I", 44))
            server_select_packet.extend(bytes(205 - len(server_select_packet)))
            
            self.login_socket.send(bytes(server_select_packet))
            
            # 接收最终响应
            self.login_socket.settimeout(2.0)
            final_resp = bytearray()
            try:
                while True:
                    chunk = self.login_socket.recv(4096)
                    if not chunk:
                        break
                    final_resp.extend(chunk)
            except socket.timeout:
                pass
            
            if len(final_resp) == 0:
                print("[-] Auth failed")
                return False
            
            session_bytes = session_16 + bytes(96)
            user_id = int(username)
            
            print(f"[+] Auth success (S{server_id})")
            return True
            
        except Exception as e:
            print(f"[-] Auth error: {e}")
            return False
    
    def connect_main_server(self, server_id):
        if server_id == 1:
            port = 1965
        elif 2 <= server_id <= 30:
            port = 1865
        elif 31 <= server_id <= 100:
            port = 1201
        else:
            print(f"[-] Invalid server: {server_id}")
            return False
        
        try:
            self.main_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.main_socket.settimeout(10)
            self.main_socket.connect(("123.206.131.236", port))
            print(f"[+] Main server connected")
            return True
        except Exception as e:
            print(f"[-] Main server failed: {e}")
            return False
    
    def main_server_login(self, server_id):
        global user_id, session_bytes
        try:
            token = build_login_token(session_bytes, server_id)
            token_modified = bytearray(token)
            token_modified[0] = server_id
            
            body = bytearray()
            body.append(0x00)
            body.extend(token_modified)
            body.extend(pack("!I", 16))
            body.extend(session_bytes[:16])
            body.extend(pack("!I", 0))
            body.append(0x30)
            body.extend(bytes(63))
            packet = Packet()
            packet.cmd_id = 201
            packet.user_id = user_id
            packet.body = bytes(body)
            packet.encrypt()
            
            packet_data = packet.data()
            self.main_socket.send(packet_data)
            
            header = self.main_socket.recv(17)
            if len(header) < 17:
                print(f"[-] Header invalid: {len(header)}")
                return False
            
            packet_len = int.from_bytes(header[:4], "big")
            body_len = packet_len - 17
            body = b""
            while len(body) < body_len:
                chunk = self.main_socket.recv(body_len - len(body))
                if not chunk:
                    break
                body += chunk
            
            response = header + body
            
            if len(response) < packet_len:
                print("[-] Response incomplete")
                return False
            
            resp_packet = Packet(response)
            resp_packet.decrypt()
            
            if resp_packet.version != 0:
                print(f"[-] Login failed: {resp_packet.version}")
                return False
            
            self.connected = True
            self.main_socket.settimeout(None)  # 取消超时，防止挂机断线
            print("[+] Login success")
            
            threading.Thread(target=self.recv_loop, daemon=True).start()
            self.start_heartbeat()
            
            return True
            
        except Exception as e:
            print(f"[-] Login error: {e}")
            return False
    
    def recv_loop(self):
        while self.connected:
            try:
                data = self.main_socket.recv(4096)
                if not data:
                    self.connected = False
                    break
                
                self.recv_buffer.extend(data)
                
                while len(self.recv_buffer) >= 4:
                    packet_len = int.from_bytes(self.recv_buffer[:4], "big")
                    if packet_len <= len(self.recv_buffer):
                        packet_data = self.recv_buffer[:packet_len]
                        self.recv_buffer = self.recv_buffer[packet_len:]
                        
                        packet = Packet(packet_data)
                        packet.decrypt()
                    else:
                        break
            except Exception:
                self.connected = False
                break

    def start_heartbeat(self):
        self.heartbeat_running = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
    
    def _heartbeat_loop(self):
        while self.heartbeat_running and self.connected:
            try:
                time.sleep(30)
                if not self.connected:
                    break
                
                packet = Packet()
                packet.cmd_id = 40
                packet.user_id = user_id
                packet.body = bytes([0x00])
                
                with self.send_lock:
                    packet.encrypt()
                    self.main_socket.send(packet.data())
                
            except Exception:
                break
    
    def stop_heartbeat(self):
        self.heartbeat_running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=1)
    
    def send_packet(self, packet):
        if not self.connected or not self.main_socket:
            return False
        try:
            with self.send_lock:
                packet.encrypt()
                self.main_socket.send(packet.data())
            return True
        except Exception:
            self.connected = False
            return False
    
    def close(self):
        self.connected = False
        self.stop_heartbeat()
        if self.login_socket:
            try:
                self.login_socket.close()
            except:
                pass
        if self.main_socket:
            try:
                self.main_socket.close()
            except:
                pass


def load_daily_packets():
    import os
    
    packets_data = os.environ.get("PACKETS_DATA")
    if not packets_data:
        # 尝试从文件加载
        try:
            if os.path.exists("封包.txt"):
                with open("封包.txt", "r", encoding="utf-8") as f:
                    packets_data = f.read()
        except:
            pass
            
    if not packets_data:
        return {}
    
    try:
        lines = packets_data.split('\n')
        items = {}
        current_name = None
        current_count = 1
        current_packets = []
        
        for line in lines:
            line = line.strip()
            if line.startswith("#") or not line:
                if current_name and current_packets:
                    items[current_name] = {
                        "count": current_count,
                        "packets": current_packets.copy()
                    }
                current_name = None
                current_packets = []
                continue
            
            if "（" in line and "）" in line:
                if current_name and current_packets:
                    items[current_name] = {
                        "count": current_count,
                        "packets": current_packets.copy()
                    }
                    current_packets = []
                
                try:
                    name_part = line.split("（")[0].strip()
                    count_part = line.split("（")[1].split("）")[0]
                    current_name = name_part
                    if current_name in items:
                        counter = 2
                        while f"{current_name}_{counter}" in items:
                            counter += 1
                        current_name = f"{current_name}_{counter}"
                    
                    try:
                        current_count = int(count_part)
                    except ValueError:
                        current_count = 1
                except IndexError:
                    continue
            elif line and current_name and len(line) >= 17:
                clean_line = line.replace("{", "0").replace("}", "0")
                if all(c in "0123456789ABCDEFabcdef" for c in clean_line):
                    current_packets.append(line)
        
        if current_name and current_packets:
            items[current_name] = {
                "count": current_count,
                "packets": current_packets.copy()
            }
        
        return items
    except Exception:
        return {}


def execute_daily_tasks(client, daily_items, custom_packets=None, server_id=100, username="", password=""):
    global user_id
    all_packets = []
    for item_name, item_data in daily_items.items():
        count = item_data.get("count", 1)
        packets = item_data.get("packets", [])
        for _ in range(count):
            for packet in packets:
                packet_hex = packet.replace("{user_id}", get_hex(user_id))
                packet_hex = packet_hex.replace("{lamu_id}", "00000000")
                all_packets.append(packet_hex)
    
    if custom_packets:
        print(f"[*] 加载 {len(custom_packets)} 自定义")
        for packet in custom_packets:
            packet_hex = packet.replace("{user_id}", get_hex(user_id))
            packet_hex = packet_hex.replace("{super_lamu_level}", "00000016")
            packet_hex = packet_hex.replace("{lamu_id}", "00000000")
            all_packets.append(packet_hex)
    
    if not all_packets:
        return False
    
    print(f"[*] 总计 {len(all_packets)} 待发送")
    success_count = 0
    fail_count = 0
    
    for i, packet_hex in enumerate(all_packets):
        retry_count = 0
        max_retries = 3
        packet_sent = False
        
        while retry_count < max_retries and not packet_sent:
            if not client.connected:
                print(f"[!] 连接已断开，尝试重连...")
                client.close()  # 清理旧资源，停止旧线程
                time.sleep(2)
                
                if not client.connect_login_server():
                    retry_count += 1
                    continue
                
                if not client.login_server_auth(username, password, server_id):
                    retry_count += 1
                    continue
                
                if not client.connect_main_server(server_id):
                    retry_count += 1
                    continue
                
                if not client.main_server_login(server_id):
                    retry_count += 1
                    continue
                
                print("[+] 重连成功")
            
            try:
                packet_hex_final = packet_hex.replace("{super_lamu_level}", "00000016")
                packet = Packet(packet_hex_final)
                if client.send_packet(packet):
                    success_count += 1
                    packet_sent = True
                else:
                    fail_count += 1
                    retry_count += 1
                    if retry_count < max_retries:
                        time.sleep(0.1)
            except Exception as e:
                fail_count += 1
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(0.1)
        
        if not packet_sent:
            print(f"[!] 封包 {i+1}/{len(all_packets)} 发送失败")
        
        time.sleep(0.05)
    
    time.sleep(5)
    
    return True


def send_online_gift_packets(client):
    packets = [
        "0000001EB0000004DB03E4F72C000000000000003D0000000100000001",
        "0000001E12000004DB03E4F72C000000000000003E0000000100000001",
        "0000001EF2000004DB03E4F72C000000000000003F0000000100000001",
        "0000001E7A000004DB03E4F72C00000000000000400000000100000001",
        "0000001E8D000004DB03E4F72C00000000000000410000000100000001",
    ]
    success = 0
    fail = 0
    for packet_hex in packets:
        try:
            packet = Packet(packet_hex)
            if client.send_packet(packet):
                success += 1
            else:
                fail += 1
        except Exception:
            fail += 1
        time.sleep(0.05)


def load_accounts():
    import os
    import json
    
    accounts_json = os.environ.get("ACCOUNTS_CONFIG")
    if not accounts_json:
        # 尝试从文件加载
        try:
            if os.path.exists("accounts_config.json"):
                with open("accounts_config.json", "r", encoding="utf-8") as f:
                    accounts_json = f.read()
            elif os.path.exists("accounts.json"):
                 with open("accounts.json", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "accounts" in data:
                        # 转换格式适配
                        acc_list = []
                        for u, p in data["accounts"].items():
                            acc_list.append({"username": u, "password": p, "server": 100, "online_minutes": 0})
                        return acc_list
        except:
            pass

    if not accounts_json:
        return []
    
    try:
        accounts = json.loads(accounts_json)
        enabled_accounts = [acc for acc in accounts if acc.get("enabled", True)]
        return enabled_accounts
    except Exception:
        return []


def process_account(account, daily_items):
    username = account["username"]
    password = account["password"]
    server = account.get("server", 100)
    online_minutes = account.get("online_minutes", 0)
    custom_packets = account.get("super_lamu_packets", [])
    
    print(f"\n[*] Account: {username} | Server: {server}")
    
    client = Client()
    
    try:
        if not client.connect_login_server():
            return False
        
        if not client.login_server_auth(username, password, server):
            return False
        
        if not client.connect_main_server(server):
            return False
        
        if not client.main_server_login(server):
            return False
        
        if not execute_daily_tasks(client, daily_items, custom_packets, server, username, password):
            return False
        
        if isinstance(online_minutes, (int, float)) and online_minutes > 0:
            hang_seconds = int(online_minutes * 60)
            print(f"[*] 开始挂机 {online_minutes} 分钟...")
            start_time = time.time()
            while time.time() - start_time < hang_seconds:
                if not client.connected:
                    print(f"[!] 挂机中断开，尝试重连...")
                    client.close()
                    try:
                        if client.connect_login_server() and \
                           client.login_server_auth(username, password, server) and \
                           client.connect_main_server(server) and \
                           client.main_server_login(server):
                            print("[+] 重连成功")
                        else:
                            time.sleep(5)
                    except Exception as e:
                        print(f"[-] 重连异常: {e}")
                        time.sleep(5)
                time.sleep(1)
                
            if online_minutes >= 100:
                # 确保发送礼物前是在线的
                if not client.connected:
                    print(f"[!] 发送礼物前重连...")
                    client.close()
                    if client.connect_login_server() and \
                       client.login_server_auth(username, password, server) and \
                       client.connect_main_server(server) and \
                       client.main_server_login(server):
                        send_online_gift_packets(client)
                else:
                    send_online_gift_packets(client)
        
        print(f"[+] Account {username} completed")
        return True
        
    except Exception as e:
        print(f"[-] Account {username} failed: {e}")
        return False
    finally:
        client.close()
        time.sleep(2)


def process_account_entry(index, total, account, daily_items):
    success = process_account(account, daily_items)
    if not success:
        raise SystemExit(1)


def main():
    accounts = load_accounts()
    if not accounts:
        return 1
    
    daily_items = load_daily_packets()
    if not daily_items:
        print("[!] 未加载到封包数据，仅发送自定义封包")
        daily_items = {}
    
    success_count = 0
    processes = []
    total = len(accounts)
    for i, account in enumerate(accounts, 1):
        p = Process(target=process_account_entry, args=(i, total, account, daily_items))
        p.start()
        processes.append(p)
    
    for p in processes:
        p.join()
        if p.exitcode == 0:
            success_count += 1
    
    return 0 if success_count == len(accounts) else 1


if __name__ == "__main__":
    sys.exit(main())
