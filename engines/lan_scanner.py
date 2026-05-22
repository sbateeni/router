import socket
import threading
from engines.utils import log
from engines.fingerprinter import Fingerprinter
from engines.platform_utils import ping_host

class LANScanner:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.subnet = ".".join(self.local_ip.split('.')[:-1]) + "."
        self.discovered_devices = []
        self.lock = threading.Lock()

    def get_local_ip(self):
        """الحصول على الأي بي المحلي للجهاز"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip

    def scan_ip(self, ip):
        """فحص أي بي محدد للتأكد من وجود جهاز ونوعه"""
        # محاولة Ping سريعة (Windows / Linux)
        try:
            if ping_host(ip):
                # إذا كان الجهاز يعمل، نحاول التعرف عليه
                for port in [80, 8000, 8080, 37777]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.3)
                        if sock.connect_ex((ip, port)) == 0:
                            # إذا وجدنا بورت مفتوح، نستخدم المحرك الذكي
                            fp = Fingerprinter(f"http://{ip}:{port}")
                            device_type = fp.identify()
                            with self.lock:
                                self.discovered_devices.append({
                                    "ip": ip,
                                    "port": port,
                                    "type": device_type
                                })
                            sock.close()
                            break
                        sock.close()
                    except: pass
        except: pass

    def run_scan(self):
        """تشغيل المسح الشامل للشبكة باستخدام الـ Threads لسرعة التنفيذ"""
        log(f"Starting LAN Scan on subnet {self.subnet}0/24...", "INFO")
        threads = []
        for i in range(1, 255):
            ip = self.subnet + str(i)
            t = threading.Thread(target=self.scan_ip, args=(ip,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
        
        return self.discovered_devices

    def display_results(self):
        """عرض النتائج بشكل منظم للمستخدم"""
        if not self.discovered_devices:
            log("No devices found in the local network.", "ERROR")
            return None

        print("\n" + "="*60)
        print("      LAN SCAN RESULTS - DEVICES DISCOVERED")
        print("="*60)
        for i, dev in enumerate(self.discovered_devices):
            print(f"  [{i+1}] IP: {dev['ip']:<15} | Type: {dev['type']:<15} | Port: {dev['port']}")
        print("="*60)
        
        try:
            choice = input("\n[?] Select Device ID to attack (or 'q' to quit): ").strip()
            if choice.lower() == 'q': return None
            idx = int(choice) - 1
            if 0 <= idx < len(self.discovered_devices):
                return self.discovered_devices[idx]
        except:
            print("Invalid selection.")
        
        return None
