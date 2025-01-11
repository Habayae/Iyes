import ctypes
import sys
import platform
import socket
import uuid
import psutil
import subprocess
import time
import struct
import ipaddress
import os
import time
import pygame
import threading
import cv2
import ipaddress
import re    
import json
import requests
import concurrent.futures
import numpy as np
import tkinter as tk
from datetime import datetime, timedelta
from scapy.all import ARP, Ether, srp
from tkinter import messagebox
from tkinter import ttk
from collections import defaultdict
from flask import Flask, request, jsonify


# ============================
# Nhóm chức năng lấy thông tin thiết bị
# ============================


# Hàm lấy thông tin hệ điều hành
def get_os_info():
    os_name = platform.system()
    os_version = platform.version()
    if os_name == "Windows":
        return f"Hệ điều hành: {os_name} {os_version}"
    return f"Hệ điều hành: {os_name} {os_version}"


# Hàm lấy tên thiết bị
def get_device_name():
    return socket.gethostname()


# Hàm lấy địa chỉ IP của thiết bị
def get_ip_address(interface_name=None):
    # Lấy danh sách các giao diện mạng
    interfaces = psutil.net_if_addrs()
    
    if interface_name:
        # Kiểm tra nếu có giao diện cụ thể được yêu cầu
        if interface_name in interfaces:
            for addr in interfaces[interface_name]:
                if addr.family == socket.AF_INET:  # Kiểm tra IPv4
                    return addr.address
        else:
            return None
    
    # Nếu không có giao diện cụ thể, lấy IP của giao diện đầu tiên có IPv4
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
    return None


# Hàm lấy địa chỉ MAC của thiết bị
def get_mac_address():
    os_name = platform.system()
    if os_name == "Windows":
        result = subprocess.run(["getmac", "/fo", "list"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "Physical" in line:
                mac = line.split(":")[1].strip()
                return mac.replace('-', ':')
    elif os_name == "Linux" or os_name == "Darwin":
        result = subprocess.run(["ifconfig"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "ether" in line:
                mac = line.split()[1]
                return mac.replace('-', ':')
    else:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2 * 6, 2)][::-1])
        return mac


# ============================
# Nhóm chức năng lấy thông tin Default Gateway
# ============================

# Hàm tính toán subnet mask
def get_subnet_mask():
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.netmask
    return None

# Hàm tìm IP Default Gateway
def calculate_default_gateway(ip, subnet_mask):
    ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
    subnet_int = struct.unpack('!I', socket.inet_aton(subnet_mask))[0]
    network_int = ip_int & subnet_int
    gateway_int = network_int + 1
    gateway_ip = socket.inet_ntoa(struct.pack('!I', gateway_int))
    return gateway_ip

# Hàm tìm MAC Default Gateway
def get_mac_address_of_gateway(ip):
    # Gửi ARP Request tới gateway để lấy MAC
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast cho tất cả các thiết bị
    arp_request_broadcast = broadcast / arp_request
    
    # Gửi yêu cầu ARP và nhận phản hồi
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    for element in answered_list:
        return element[1].hwsrc  # MAC Address của gateway

    return None 


# ============================
# Nhóm chức năng lấy thông tin thiết bị khác
# ============================


# Hàm tìm kiếm các thiết bị kết nối tới default gateway
def get_devices_connected_to_gateway():
    devices = []
    try:
        arp_output = subprocess.check_output("arp -a", shell=True, text=True)
        for line in arp_output.splitlines():
            # Lọc các thiết bị có địa chỉ IP và MAC
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                mac = parts[1]
                devices.append((ip, mac))
    except subprocess.CalledProcessError as e:
        print(f"Lỗi khi lấy thông tin ARP: {e}")
    return devices


# ============================
# Chức năng phát hiện ARP Poisoning
# ============================


# Hàm phát hiện ARP Poisoning
def detect_arp_poisoning(initial_ip_mac_list, arp_poison_tree):
    print(f"Initial IP-MAC list: {initial_ip_mac_list}")
    current_ip_mac_map = defaultdict(list)

    # Quét các thiết bị kết nối tới default gateway
    devices = get_devices_connected_to_gateway()

    # Lấy IP và MAC của các thiết bị kết nối
    for ip, mac in devices:
        current_ip_mac_map[ip].append(mac)

    # Kiểm tra và so sánh với các giá trị ban đầu
    poison_detected = False
    for ip, mac_list in current_ip_mac_map.items():
        unique_macs = set(mac_list)

        # Nếu có nhiều hơn một MAC cho một IP, có thể là ARP poisoning
        if len(unique_macs) > 1:
            print(f"Phát hiện ARP Poisoning từ {ip}") 
            poison_detected = True
            arp_poison_tree.insert("", "end", text=f"Phát hiện ARP Poisoning từ {ip}", values=("Phát hiện ARP Poisoning từ " + ip, get_formatted_time()))

        # So sánh MAC hiện tại với MAC gốc
        initial_mac_for_ip = next((mac for ip_, mac in initial_ip_mac_list if ip_ == ip), None)
        if initial_mac_for_ip and initial_mac_for_ip != mac_list[0]:
            print(f"Phát hiện thay đổi MAC của {ip}!") 
            poison_detected = True
            arp_poison_tree.insert("", "end", text=f"Thay đổi địa chỉ MAC của {ip}", values=("Thay đổi địa chỉ MAC từ " + ip, get_formatted_time()))

    if not poison_detected:
        print("Không phát hiện ARP Poisoning.")
        arp_poison_tree.insert("", "end", text="Không phát hiện ARP Poisoning", values=("Không phát hiện ARP Poisoning", get_formatted_time()))


# Hàm lưu trữ thông tin IP và MAC ban đầu của các thiết bị
def store_initial_ip_mac():
    initial_ip_mac_list = []

    # Lấy thông tin về các thiết bị kết nối với default gateway
    devices = get_devices_connected_to_gateway()

    # Lưu trữ các IP và MAC ban đầu
    for ip, mac in devices:
        initial_ip_mac_list.append((ip, mac))

    # In ra thông tin gốc
    print("Lưu trữ thông tin gốc IP-MAC:")
    for ip, mac in initial_ip_mac_list:
        print(f"IP: {ip} -> MAC: {mac}")

    return initial_ip_mac_list

initial_ip_mac_map = store_initial_ip_mac()


# ============================
# Chức năng phát hiện IP Spoofing
# ============================            


# Hàm phát hiện IP Spoofing
def detect_ip_spoofing(initial_ip_mac_list, ip_spoof_tree):
    # Lấy thông tin hiện tại về các thiết bị kết nối với default gateway
    devices = get_devices_connected_to_gateway()

    # Duyệt qua các thiết bị trong mạng
    for ip, mac in devices:
        # Kiểm tra nếu IP có trong danh sách gốc và MAC không khớp
        for initial_ip, initial_mac in initial_ip_mac_list:
            if ip == initial_ip:
                if mac != initial_mac:
                    # Phát hiện sự thay đổi IP-MAC
                    ip_spoof_tree.insert("", "end", values=("Phát hiện IP Spoofing từ " + ip, get_formatted_time()))

    ip_spoof_tree.insert("", "end", values=("Không phát hiện IP Spoofing", get_formatted_time()))


# ============================
# Hàm chính thực thi chương trình
# ============================


# Hàm quét mạng
def scan_network_info(my_device_tree, scan_result_tree, scan_count):
    os_info = get_os_info()  
    device_name = get_device_name()  
    ip_address = get_ip_address() 
    mac_address = get_mac_address() 

    subnet_mask = get_subnet_mask()
    default_gateway = None
    gateway_mac = None

    if subnet_mask:
        default_gateway = calculate_default_gateway(ip_address, subnet_mask)
        gateway_mac = get_mac_address_of_gateway(default_gateway)

    my_device_tree.insert("", "end", values=(os_info, device_name, ip_address, mac_address, subnet_mask, default_gateway, gateway_mac))

    devices = get_devices_connected_to_gateway()

    if scan_count > 1:
        scan_result_tree.insert("", "end", values=("", "", ""))
        scan_result_tree.insert("", "end", values=("", "", ""))

    if devices:
        first_device = True  
        for ip, mac in devices:
            if first_device:
                scan_result_tree.insert("", "end", values=(scan_count, ip, mac))
                first_device = False 
            else:
                scan_result_tree.insert("", "end", values=("", ip, mac)) 


# Hàm kiểm tra các dấu hiệu tấn công
def check_attacks(ip_spoof_tree, arp_poison_tree):
    subnet_mask = get_subnet_mask()
    if subnet_mask:
        gateway_ip = calculate_default_gateway(get_ip_address(), subnet_mask)

        initial_ip_mac_list = store_initial_ip_mac()

        # Phát hiện ARP Poisoning
        print("\nĐang kiểm tra ARP Poisoning...")
        arp_thread = threading.Thread(target=detect_arp_poisoning, args=(initial_ip_mac_list, arp_poison_tree))
        arp_thread.start()

        # Phát hiện IP Spoofing
        print("\nĐang kiểm tra IP Spoofing...")
        ip_thread = threading.Thread(target=detect_ip_spoofing, args=(initial_ip_mac_list, ip_spoof_tree))
        ip_thread.start()

        arp_thread.join()
        ip_thread.join()
        

# ===========================
# Hàm xử lý các thao tác quét và phát hiện
# ===========================


scan_running = False
detection_running = False


# Hàm quét mạng
def start_scan(my_device_tree, scan_result_tree):
    global scan_running
    scan_running = True
    scan_count = 0  
    start_scan_button.config(state="disabled")
    print("Bắt đầu quét mạng...")

    def scan_loop():
        nonlocal scan_count
        while scan_running:
            scan_count += 1  
            scan_network_info(my_device_tree, scan_result_tree, scan_count)
            time.sleep(30)

    scan_thread = threading.Thread(target=scan_loop)
    scan_thread.daemon = True
    scan_thread.start()

def update_scan_count_label(scan_count):
    scan_count_label.config(text=f"Lần quét: {scan_count}")


# Hàm bắt đầu phát hiện tấn công 
def start_detection(ip_spoof_tree, arp_poison_tree):
    global detection_running
    detection_running = True
    subnet_mask = get_subnet_mask
    start_detection_button.config(state="disabled") 
    print("Bắt đầu phát hiện IP, ARP,...")

    def detection_loop():
        while detection_running:
            target_ip = get_ip_address() 

            print("\nĐang kiểm tra ARP Poisoning...")
            threading.Thread(target=detect_arp_poisoning, args=(initial_ip_mac_map, arp_poison_tree)).start()

            print("\nĐang kiểm tra IP Spoofing...")
            threading.Thread(target=detect_ip_spoofing, args=(initial_ip_mac_map, ip_spoof_tree)).start()

            time.sleep(20)  

    detection_thread = threading.Thread(target=detection_loop)
    detection_thread.daemon = True 
    detection_thread.start()


# Dừng quét mạng
def stop_scan():
    global scan_running
    scan_running = False
    start_scan_button.config(state="normal")
    print("Dừng quét mạng")


# Hàm dừng các luồng phát hiện
def stop_detection():
    global detection_running
    detection_running = False
    start_detection_button.config(state="normal")
    print("Dừng phát hiện")


# ===========================
# Hàm lưu lịch sử cảnh báo và gửi đi
# ===========================


stop_event = threading.Event()

def send_json_async(file_path):
    threading.Thread(target=send_json, args=(file_path,)).start()

# Lưu lịch sử quét và phát hiện vào file log
def save_history(ip_spoof_tree, arp_poison_tree):
    log_file = "detection_log.json"
    history_data = []

    ip_rows = ip_spoof_tree.get_children()
    arp_rows = arp_poison_tree.get_children()

    # Lấy IP của thiết bị gửi
    sender_ip = get_ip_address()
    if not sender_ip:
        sender_ip = "Không thể xác định IP"

    # Duyệt qua các tree view và thu thập dữ liệu
    max_rows = max(len(ip_rows), len(arp_rows))
    for i in range(max_rows):
        ip_warning = ip_spoof_tree.item(ip_rows[i])['values'][0] if i < len(ip_rows) else "Không phát hiện IP Spoofing"
        ip_time = ip_spoof_tree.item(ip_rows[i])['values'][1] if i < len(ip_rows) else "N/A"
        arp_warning = arp_poison_tree.item(arp_rows[i])['values'][0] if i < len(arp_rows) else "Không phát hiện ARP Poisoning"
        arp_time = arp_poison_tree.item(arp_rows[i])['values'][1] if i < len(arp_rows) else "N/A"
        
        entry = {
            "ip_warning": ip_warning,
            "ip_time": ip_time,
            "arp_warning": arp_warning,
            "arp_time": arp_time
        }
        history_data.append(entry)

    # Kiểm tra nếu file log đã tồn tại
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            existing_data = json.load(f)
        existing_data.append({
            "scan_time": get_formatted_time(),
            "sender_ip": sender_ip,
            "history": history_data
        })
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, ensure_ascii=False, indent=4)
    else:
        data_to_save = [{
            "scan_time": get_formatted_time(),
            "sender_ip": sender_ip,
            "history": history_data
        }]
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(data_to_save, f, ensure_ascii=False, indent=4)

    print(f"Lịch sử đã được lưu từ thiết bị có IP {sender_ip}.")

    send_json_async(log_file)

# Hàm kiểm tra xem có thiết bị nào mở cổng 5000 (IyesSeeing.py) tại địa chỉ IP không
def check_device_running_iyesseeing(ip):
    try:
        # Kiểm tra kết nối TCP tới cổng 5000
        socket.setdefaulttimeout(1)  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Tạo socket TCP
        sock.connect((ip, 5000))  # Kết nối tới IP và cổng 5000
        sock.close()  # Đóng kết nối
        return True 
    except (socket.timeout, socket.error):
        return False

# Hàm gửi file JSON tới một thiết bị có cài ứng dụng IyesSeeing.py
def send_json_to(file_path, target_ip):
    url = f"http://{target_ip}:5000/upload-log"  # Địa chỉ của ứng dụng IyesSeeing
    files = {'file': open(file_path, 'rb')}  # Mở file JSON để gửi
    
    try:
        response = requests.post(url, files=files)  # Gửi POST request với file
        if response.status_code == 200:
            print(f"File đã được gửi thành công tới {target_ip}!")
        else:
            print(f"Lỗi khi gửi file tới {target_ip}: {response.json()['message']}")
    except requests.exceptions.RequestException as e:
        print(f"Lỗi kết nối tới {target_ip}: {str(e)}")

def get_ip_range(subnet):
    ip_parts = subnet.split('.')  
    base_ip = '.'.join(ip_parts[:-1]) + '.'  
    last_octet = int(ip_parts[-1]) 
    
    return [f"{base_ip}{i}" for i in range(1, 255)]

# Hàm gửi file JSON tới tất cả các thiết bị có cài đặt IyesSeeing.py
def send_json(file_path):
    ip = get_ip_address() 
    if not ip:
        print("Không thể xác định địa chỉ IP của thiết bị.")
        return
    
    # Lấy dải IP của LAN (mạng con)
    ip_range = get_ip_range(ip)
    
    while True:
        found_device = False 

        # Quét toàn bộ dải IP
        with concurrent.futures.ThreadPoolExecutor(max_workers=255) as executor:
            futures = []
            for ip in ip_range:
                if ip.startswith('127.'):
                    continue
                
                futures.append(executor.submit(check_and_send_file, ip, file_path))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result: 
                    found_device = True
                    break
        
        if not found_device:
            print("Không có thiết bị nào nhận file. Đang lặp lại quá trình quét...")
            time.sleep(10) 
        else:
            break

# Hàm kiểm tra và gửi file tới thiết bị nếu ứng dụng IyesSeeing.py đang chạy
def check_and_send_file(ip, file_path):
    print(f"Đang kiểm tra {ip}...")

    # Kiểm tra xem ứng dụng IyesSeeing.py có đang chạy trên cổng 5000 không
    if check_device_running_iyesseeing(ip):  # Kiểm tra cổng 5000
        print(f"Phát hiện ứng dụng IyesSeeing.py tại {ip}. Đang gửi file...")
        send_json_to(file_path, ip)  # Gửi file JSON nếu cổng 5000 mở
        return True 
    
    return False  


# Hàm tìm kiếm các thiết bị trong mạng
def get_valid_device_ips():
    valid_ips = []
    ip = get_ip_address()
    if ip:
        ip_range = get_ip_range(ip)
        for ip in ip_range:
            if ip.startswith('127.'):
                continue
            # Kiểm tra ứng dụng IyesSeeing.py có đang chạy trên cổng 5000 không
            if check_device_running_iyesseeing(ip):
                valid_ips.append(ip)
    return valid_ips


# Xóa các kết quả hiển thị trên giao diện
def clear_results(scan_result_tree, ip_spoof_tree, arp_poison_tree, my_device_tree):

    for tree in [scan_result_tree, ip_spoof_tree, arp_poison_tree, my_device_tree]:
        for item in tree.get_children():
            tree.delete(item)


# Thoát chương trình 
def on_exit():
    result = messagebox.askquestion("Exit", "Bạn chắc chắn muốn thoát ?")
    
    if result == "yes":
        root.quit() 


def exit_welcome():
    root = tk.Tk()
    root.withdraw() 
    root.iconbitmap(icon_path)  

    result = messagebox.askquestion("Exit", "Bạn chắc chắn muốn thoát ?", icon=messagebox.QUESTION)
    
    if result == "yes":
        sys.exit() 
    

# Định dạng thời gian 
def get_formatted_time():
    return datetime.now().strftime("%m/%d/%Y %a/%H:%M")


# Hàm xử lý sự kiện khi nhấn nút "Enter Scan"
def on_enter_scan():
    pygame.quit() 
    main_gui() 


# ===========================
# Các tài nguyên
# ===========================

# Hàm trả về đường dẫn tới tài nguyên.
def get_resource_path(filename):

    if hasattr(sys, '_MEIPASS'):
        # Nếu chương trình đang chạy dưới dạng tệp .exe, lấy đường dẫn từ thư mục tạm
        return os.path.join(sys._MEIPASS, filename)
    else:
        # Nếu chạy từ mã nguồn, sử dụng đường dẫn hiện tại
        return os.path.join(os.path.dirname(__file__), filename)

icon_path = get_resource_path("icon.ico")
video_path = get_resource_path("video.mp4")
audio_path = get_resource_path("sound.mp3")

# ===========================
# Giao diện người dùng
# ===========================

# Hàm tạo giao diện tkinter
is_main_gui_open = False

def main_gui():

    global is_main_gui_open
    global root
    global start_scan_button
    global stop_scan_button
    global start_detection_button
    global stop_detection_button

    if is_main_gui_open:
        return  

    is_main_gui_open = True

    # Tạo cửa sổ chính
    root = tk.Tk()
    root.lift()
    root.title("IyesWatching")
    root.geometry("900x600")
    root.iconbitmap(icon_path)

    root.resizable(True, True) 

    window_width = 900
    window_height = 600

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    position_top = int((screen_height - window_height) / 2)
    position_right = int((screen_width - window_width) / 2)

    root.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

# ===========================
# Khung chứa các nút điều khiển
# ===========================

    control_frame = tk.Frame(root)
    control_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)  

    # Các nút điều khiển
    exit_button = tk.Button(control_frame, text="Exit", command=on_exit, width=12, height=1, relief="solid", padx=8, pady=5, font=("Times New Roman", 10, "bold"), fg="black", bg="white")
    exit_button.pack(side=tk.LEFT, padx=8)

    start_scan_button = tk.Button(control_frame, text="Start Scan", command=lambda: start_scan(my_device_tree, scan_result_tree), width=12, height=1, relief="solid", padx=8, pady=5, font=("Times New Roman", 10, "bold"), fg="black", bg="white")
    start_scan_button.pack(side=tk.LEFT, padx=8)

    start_detection_button = tk.Button(control_frame, text="Start Detection", command=lambda: start_detection(ip_spoof_tree, arp_poison_tree), width=12, height=1, relief="solid", padx=8, pady=5, font=("Times New Roman", 10, "bold"), fg="black", bg="white")
    start_detection_button.pack(side=tk.LEFT, padx=8)

    stop_scan_button = tk.Button(control_frame, text="Stop Scan", command=stop_scan, width=12, height=1, relief="solid", padx=8, pady=5, font=("Times New Roman", 10, "bold"), fg="black", bg="white")
    stop_scan_button.pack(side=tk.LEFT, padx=8)

    stop_detection_button = tk.Button(control_frame, text="Stop Detection", command=stop_detection, width=12, height=1, relief="solid", padx=8, pady=5, font=("Times New Roman", 10, "bold"), fg="black", bg="white")
    stop_detection_button.pack(side=tk.LEFT, padx=8)

    save_history_button = tk.Button(control_frame, text="Save History", command=lambda: save_history(ip_spoof_tree, arp_poison_tree), width=12, height=1, relief="solid", padx=8, pady=5, font=("Times New Roman", 10, "bold"), fg="black", bg="white")
    save_history_button.pack(side=tk.LEFT, padx=8)

    clear_button = tk.Button(control_frame, text="Clear", command=lambda: clear_results(scan_result_tree, ip_spoof_tree, arp_poison_tree, my_device_tree), width=12, height=1, relief="solid", padx=8, pady=5, font=("Times New Roman", 10, "bold"), fg="black", bg="white")
    clear_button.pack(side=tk.LEFT, padx=8)



# ===========================
# Đồng hồ thời gian thực
# ===========================
    
    time_label = tk.Label(root, font=("Times New Roman", 20))  
    time_label.pack(side=tk.BOTTOM, pady=5) 

    def update_time():
        current_time = datetime.utcnow() + timedelta(hours=7)  # Thời gian GMT+7
        time_label.config(text=current_time.strftime("%H:%M:%S"))
        time_label.after(1000, update_time)

    update_time()

# ===========================
# Khung chứa bảng kết quả
# ===========================

    # Tạo frame chứa các bảng
    result_frame = tk.Frame(root)
    result_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Tạo Notebook (Tabbed Interface)
    notebook = ttk.Notebook(result_frame)
    notebook.pack(fill=tk.BOTH, expand=True)

# ===========================
# Bảng hiển thị kết quả quét mạng
# ===========================

    # Tạo frame cho tab "Scan Result"
    frame_scan_result = ttk.Frame(notebook)
    notebook.add(frame_scan_result, text="Scan Result")

    # Tạo Treeview cho Scan Result
    scan_result_tree = ttk.Treeview(frame_scan_result, columns=("Scan Count", "IP", "MAC"))
    scan_result_tree.heading("Scan Count", text="Số lần quét")
    scan_result_tree.heading("IP", text="IP")
    scan_result_tree.heading("MAC", text="MAC")
    scan_result_tree.column("Scan Count", anchor="center")
    scan_result_tree.column("IP", anchor="center")
    scan_result_tree.column("MAC", anchor="center")

    scan_result_tree.column("#0", width=0, stretch=tk.NO)
    scan_result_tree["displaycolumns"] = ("Scan Count", "IP", "MAC")

    scrollbar = ttk.Scrollbar(frame_scan_result, orient="vertical", command=scan_result_tree.yview)
    scan_result_tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    scan_result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    
# ===========================
# Bảng phát hiện IP Spoofing
# ===========================

    # Frame và Treeview cho IP Spoofing Detection
    frame_ip_spoof = ttk.Frame(notebook)
    notebook.add(frame_ip_spoof, text="IP Spoofing Detection")

    # Tạo Treeview cho IP Spoofing
    ip_spoof_tree = ttk.Treeview(frame_ip_spoof, columns=("Warning", "Time"), show="headings")
    ip_spoof_tree.heading("Warning", text="Warning")
    ip_spoof_tree.heading("Time", text="Time")

    scroll_y_ip_spoof = ttk.Scrollbar(frame_ip_spoof, orient="vertical", command=ip_spoof_tree.yview)
    scroll_y_ip_spoof.pack(side=tk.RIGHT, fill=tk.Y)
    ip_spoof_tree.configure(yscrollcommand=scroll_y_ip_spoof.set)

    ip_spoof_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    

# ===========================
# Bảng phát hiện ARP Poisoning
# ===========================

    # Frame và Treeview cho ARP Poisoning Detection
    frame_arp_poison = ttk.Frame(notebook)
    notebook.add(frame_arp_poison, text="ARP Poisoning Detection")

    # Tạo Treeview cho ARP Poisoning
    arp_poison_tree = ttk.Treeview(frame_arp_poison, columns=("Warning", "Time"), show="headings")
    arp_poison_tree.heading("Warning", text="Warning")
    arp_poison_tree.heading("Time", text="Time")

    # Tạo thanh cuộn dọc cho ARP Poisoning
    scroll_y_arp_poison = ttk.Scrollbar(frame_arp_poison, orient="vertical", command=arp_poison_tree.yview)
    scroll_y_arp_poison.pack(side=tk.RIGHT, fill=tk.Y)
    arp_poison_tree.configure(yscrollcommand=scroll_y_arp_poison.set)

    arp_poison_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)


# ===========================
# Bảng hiển thị thông tin thiết bị gốc
# ===========================

    # Tạo frame cho tab "My Device"
    frame_my_device = ttk.Frame(notebook)
    notebook.add(frame_my_device, text="My Device")

    # Tạo Treeview cho My Device
    my_device_tree = ttk.Treeview(frame_my_device, columns=("OS", "Name", "IP", "MAC", "Subnet Mask", "Default Gateway", "MAC Default Gateway"))
    my_device_tree.heading("OS", text="OS")
    my_device_tree.heading("Name", text="Name")
    my_device_tree.heading("IP", text="IP")
    my_device_tree.heading("MAC", text="MAC")
    my_device_tree.heading("Subnet Mask", text="Subnet Mask")
    my_device_tree.heading("Default Gateway", text="Default Gateway")
    my_device_tree.heading("MAC Default Gateway", text="MAC Default Gateway")

    my_device_tree.column("#0", width=0, stretch=tk.NO)
    my_device_tree["displaycolumns"] = ("OS", "Name", "IP", "MAC", "Subnet Mask", "Default Gateway", "MAC Default Gateway")
    my_device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)


# ===========================
# Chạy ứng dụng
# ===========================

    root.protocol("WM_DELETE_WINDOW", lambda: on_tkinter_exit(root))
    root.mainloop()

def on_tkinter_exit(root):
    global is_main_gui_open
    answer = messagebox.askquestion("Xác nhận thoát", "Bạn có chắc chắn muốn thoát?")
    
    if answer == 'yes':
        is_main_gui_open = False
        root.quit()
# ===========================
# Giao diện chào mừng
# ===========================

# Khởi tạo Pygame
def welcome():
    pygame.init()

    # Thiết lập cửa sổ hiển thị video
    screen_width = 1200 
    screen_height = 675
    welcome_window = pygame.display.set_mode(
        (screen_width, screen_height), pygame.RESIZABLE
    )
    pygame.display.set_caption("IyesWatching")
    icon = pygame.image.load(icon_path)
    pygame.display.set_icon(icon)


    # ===========================
    # Phát âm thanh
    # ===========================

    def play_sound():
        global current_sound
        if not pygame.mixer.get_init():
            pygame.mixer.init()

        if pygame.mixer.music.get_busy():
            pygame.mixer.music.stop()

        pygame.mixer.music.load(audio_path)

        pygame.mixer.music.set_volume(0.5)
        pygame.mixer.music.play()
        current_sound = pygame.mixer.music

    def stop_sound():
        global current_sound
        if pygame.mixer.music.get_busy():
            pygame.mixer.music.stop()
            current_sound = None

    play_sound()

    button_font = pygame.font.SysFont("Times New Roman", 16)
    start_button = pygame.Rect(20, 20, 120, 40)
    exit_button = pygame.Rect(20, 70, 120, 40)

    def draw_buttons():
        pygame.draw.rect(welcome_window, (200, 200, 200), start_button)
        pygame.draw.rect(welcome_window, (200, 200, 200), exit_button)

        start_text = button_font.render("Enter Scan", True, (0, 0, 0))
        exit_text = button_font.render("Exit", True, (0, 0, 0))

        start_text_rect = start_text.get_rect(center=start_button.center)
        exit_text_rect = exit_text.get_rect(center=exit_button.center)

        welcome_window.blit(start_text, start_text_rect.topleft)
        welcome_window.blit(exit_text, exit_text_rect.topleft)

    # Hàm để phát video
    def play_video_pygame(video_path):
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            print("Lỗi mở video.")
            return

        fps = cap.get(cv2.CAP_PROP_FPS)
        delay = int(1000 / fps)  # Thời gian trễ giữa các khung hình

        running = True
        while running:
            for event in pygame.event.get():
                if event.type == pygame.QUIT:  
                    exit_welcome() 

                if event.type == pygame.MOUSEBUTTONDOWN:
                    pos = pygame.mouse.get_pos()
                    if start_button.collidepoint(pos):
                        on_enter_scan()  
                    elif exit_button.collidepoint(pos):
                        exit_welcome()

                if event.type == pygame.KEYDOWN:
                    if event.key in (pygame.K_RETURN, pygame.K_KP_ENTER):
                        on_enter_scan() 
                    elif event.key == pygame.K_ESCAPE:
                        exit_welcome()  

            if not pygame.display.get_surface():
                break

            ret, frame = cap.read()
            if not ret:
                cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                continue

            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frame_resized = cv2.resize(
                frame_rgb, (welcome_window.get_width(), welcome_window.get_height())
            )
            frame_surface = pygame.surfarray.make_surface(
                np.transpose(frame_resized, (1, 0, 2))
            )

            welcome_window.fill((0, 0, 0)) 
            welcome_window.blit(frame_surface, (0, 0))
            draw_buttons()
            pygame.display.flip()
            pygame.time.wait(delay)

        cap.release()
        pygame.quit()
        sys.exit() 


    play_video_pygame(video_path)

# Hàm thực thi
def main():

    welcome()
    main_gui()

if __name__ == "__main__":
    main()
