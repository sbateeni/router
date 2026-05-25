# تيليجرام + التشغيل المحلي — شرح المشاكل والحل

## أمر تشغيل واحد

```bash
cd ~/router
bash run.sh
```

(`start.sh` يوجّه إلى `run.sh` — نفس الشيء.)

---

## ماذا يفعل `run.sh`؟

```
┌─────────────────────────────────────────────────────────┐
│  bash run.sh  (طرفية واحدة)                              │
├─────────────────────────────────────────────────────────┤
│  ① يفحص .env (توكن + رقم حسابك)                         │
│  ② يشغّل البوت في الخلفية → logs/telegram.log          │
│  ③ يعرض قائمة [1]–[9] للمسح من Kali                     │
│  ④ عند مسح من تيليجرام → أسطر [SCAN] في نفس الطرفية     │
└─────────────────────────────────────────────────────────┘
```

| من أين تبدأ المسح؟ | أين ترى التقدّم؟ |
|-------------------|------------------|
| تيليجرام `@H_the_box_bot` | `[SCAN]` في طرفية `run.sh` + تقرير في التيليجرام |
| القائمة `[1]` أو `[8]` | مباشرة في الطرفية |

---

## لماذا حدثت مشاكل تيليجرام؟

### 1) `.env` غير موجود على Kali

- ملف `.env` **لا يُرفع إلى GitHub** (فيه التوكن السري).
- `git pull` ينقل الكود فقط، **ليس** التوكن.
- **الحل:** نسخ `.env` من Windows إلى Kali:
  ```bash
  scp .env kali:~/router/.env
  ```

### 2) `git pull` توقف (تعديلات محلية)

رسالة مثل: `would be overwritten by merge`

- على Kali عدّلت ملفات يدوياً فـ Git رفض التحديث.
- بقيت على **كود قديم** بدون إصلاحات البوت.
- **الحل:**
  ```bash
  git checkout -- bin/telegram_daemon.py scripts/telegram_service.sh
  git pull
  ```

### 3) عمليتان منفصلتان (هذا طبيعي وليس خطأ)

| العملية | الدور |
|---------|--------|
| `telegram_daemon.py` (خلفية) | يستمع لـ `/start` و IP من تيليجرام |
| `run.sh` (أمامية) | قائمة المسح المحلي |

لا يمكن أن يطبع البوت داخل نفس سطر `read` للقائمة — لذلك أُضيف **`logs/LIVE_SCAN.log`** وأسطر **`[SCAN]`**.

### 4) خطأ `'service'` أثناء المسح

- خطأ برمجي عند تحليل منافذ Nmap (سطر OS بدون `service`).
- **مُصلَح** في `core/classic/context.py` — يحتاج `git pull`.

### 5) استخدام `python3` بدل `.venv`

على Kali استخدم دائماً:

```bash
.venv/bin/python scripts/check_telegram_env.py
```

`run.sh` يختار `.venv/bin/python` تلقائياً.

---

## أوامر مفيدة

```bash
# حالة البوت
bash scripts/telegram_service.sh status

# إيقاف / تشغيل البوت فقط
bash scripts/telegram_service.sh stop
bash scripts/telegram_service.sh start

# فحص .env
.venv/bin/python scripts/check_telegram_env.py

# متابعة المسح الحي
tail -f logs/LIVE_SCAN.log
tail -f targets/213.244.79.195/SCAN_TRANSCRIPT.txt
```

---

## `.env` الصحيح

```env
TELEGRAM_BOT_TOKEN=123456789:AA...   # من @BotFather
TELEGRAM_CHAT_ID=6874845252          # رقم حسابك — ليس رقم البوت
TELEGRAM_AUTO=1
```

`TELEGRAM_CHAT_ID` = معرّفك من [@userinfobot](https://t.me/userinfobot)، وليس `8965930335` (رقم البوت).
