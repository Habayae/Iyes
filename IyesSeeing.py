import os
import sys
import threading
from flask import Flask, request
import json
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import psutil
import socket
import platform
import subprocess
import uuid
import requests


# Hàm lấy địa chỉ IP của thiết bị
def get_ip_address(interface_name=None):
    interfaces = psutil.net_if_addrs()
    
    if interface_name:
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


# Hàm trả về đường dẫn tới tài nguyên.
def get_resource_path(filename):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, filename)
    else:
        return os.path.join(os.path.dirname(__file__), filename)


icon_path = get_resource_path("icon.ico")

app = Flask(__name__)

# Hàm đọc và hiển thị nội dung file JSON
def load_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


# Hàm hiển thị nội dung của file JSON
def show_json_in_text(file_path):
    root = tk.Tk()
    root.title("Cảnh báo")

    root.iconbitmap(icon_path) 

    frame = ttk.Frame(root)
    frame.pack(fill=tk.BOTH, expand=True)

    tree = ttk.Treeview(frame, columns=("Scan Time", "Sender IP", "ARP Warning", "IP Warning"), show="headings")
    
    tree.heading("Scan Time", text="Thời gian quét")
    tree.heading("Sender IP", text="IP gửi")
    tree.heading("ARP Warning", text="Cảnh báo ARP")
    tree.heading("IP Warning", text="Cảnh báo IP")
    
    tree.column("Scan Time", width=150)
    tree.column("Sender IP", width=150)
    tree.column("ARP Warning", width=250)
    tree.column("IP Warning", width=250)
    
    scroll_y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
    tree.configure(yscrollcommand=scroll_y.set)

    tree.pack(fill=tk.BOTH, expand=True)

    # Đọc dữ liệu từ file JSON
    data = load_json_file(file_path)

    # Hiển thị dữ liệu vào bảng Treeview
    for entry in data:
        scan_time = entry["scan_time"]
        sender_ip = entry.get("sender_ip", "N/A")
        for history_entry in entry["history"]:
            ip_warning = history_entry["ip_warning"]
            ip_time = history_entry["ip_time"]
            arp_warning = history_entry["arp_warning"]
            arp_time = history_entry["arp_time"]
            
            ip_display = f"{ip_warning} ({ip_time})"
            arp_display = f"{arp_warning} ({arp_time})"
            
            tree.insert("", tk.END, values=(scan_time, sender_ip, arp_display, ip_display))
    
    root.mainloop()



# Hàm xử lý khi nhận được file JSON qua POST
@app.route('/upload-log', methods=['POST'])
def upload_log():
    file = request.files['file']
    if file:
        # Đảm bảo thư mục "received_files" tồn tại
        os.makedirs("received_files", exist_ok=True)
        
        # Lưu file vào thư mục 'received_files'
        file_path = os.path.join("received_files", file.filename)
        file.save(file_path)
        print(f"File {file.filename} đã được lưu tại {file_path}")
        
        # Sau khi lưu, hiển thị nội dung của file
        show_json_in_text(file_path)
        return "File received successfully", 200
    
    return "No file uploaded", 400


def run_flask():
    app.run(debug=False, host='0.0.0.0', port=5000)

if __name__ == "__main__":

    local_ip = get_ip_address() 

    print(f"Địa chỉ IP của thiết bị: {local_ip}")

    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True 
    flask_thread.start()

    
    print("Ứng dụng Flask đang chạy ngầm, đợi file JSON từ GUI...")


    flask_thread.join()
