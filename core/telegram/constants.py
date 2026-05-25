"""Telegram bot constants — commands menu and attack modes."""

MAX_QUEUE_SIZE = 10

BOT_COMMANDS = [
    ("start", "بدء — ترحيب ومساعدة"),
    ("help", "قائمة الأوامر"),
    ("engine", "Device Engine — AUTO-PWN"),
    ("osint", "Social OSINT — email/phone/user"),
    ("lan", "فحص الشبكة المحلية LAN"),
    ("history", "أهداف مسحّة سابقاً"),
    ("poc", "GitHub PoC scraper"),
    ("update", "تحديث المشروع والأدوات"),
    ("decepticon", "سلسلة Decepticon"),
    ("status", "حالة المسح الحالي"),
    ("queue", "قائمة الانتظار"),
    ("cancel", "إلغاء الاختيار"),
    ("clearqueue", "مسح قائمة الانتظار"),
]

# selection, label (Arabic), profile override
ATTACK_MODES = [
    (1, "مسح كامل — كل الأدوات", "normal"),
    (1, "مسح عميق — كل الأدوات مدمجة", "deep"),
    (21, "Device Engine — AUTO-PWN", "normal"),
    (2, "Nmap فقط", "normal"),
    (3, "Nuclei فقط", "normal"),
    (4, "Dirsearch — مسارات", "normal"),
    (5, "SQLMap — SQLi", "normal"),
    (6, "RouterSploit", "normal"),
    (7, "Ingram — كاميرات", "normal"),
    (8, "Hydra — كلمات مرور", "normal"),
    (9, "FFUF — fuzz", "normal"),
    (10, "GAU — URLs", "normal"),
    (17, "Nikto — فحص ويب", "normal"),
    (18, "WhatWeb — بصمة", "normal"),
    (19, "Nmap vuln scripts", "normal"),
]
