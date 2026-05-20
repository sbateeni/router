import subprocess
import os

TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")

def run_cmd(command, capture=False, log_file=None):
    """
    دالة مساعدة لتشغيل الأوامر وحفظ المخرجات إذا تم تحديد log_file.
    """
    try:
        print(f"\n[>] Executing: {' '.join(command) if isinstance(command, list) else command}")
        
        # التقاط المخرجات دائماً إذا كان لدينا ملف لحفظه
        if capture or log_file:
            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout + "\n" + result.stderr
            
            # حفظ المخرجات في الملف إذا طُلب ذلك
            if log_file:
                with open(log_file, "w", encoding="utf-8") as f:
                    f.write(output)
                    
            if capture:
                return True, output
            else:
                print(output) # طباعة المخرجات للمستخدم
                return result.returncode == 0, ""
        else:
            result = subprocess.run(command)
            return result.returncode == 0, ""
    except Exception as e:
        print(f"[-] Failed to execute command: {e}")
        return False, str(e)
