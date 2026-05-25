# التشغيل

```bash
cd ~/router
bash run.sh
```

**ملف واحد فقط.** يبدأ تيليجرام تلقائياً ويعرض القائمة.

| الخيار | الوظيفة |
|--------|---------|
| [1]–[8] | مسح من Kali |
| [9] | تحديث من GitHub |
| تيليجرام | @H_the_box_bot — أرسل IP |

## .env على Kali

لا يُرفع مع git. انسخه من Windows:

```bash
scp .env kali:~/router/.env
```

```env
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=6874845252
```

## مسح من تيليجرام

- التقرير يصل في التيليجرام عند الانتهاء
- تفاصيل المسح: `targets/IP/SCAN_TRANSCRIPT.txt`

## إن علقت طرفية tmux مقسومة (قديم)

```bash
tmux kill-session -t autopwn
tmux kill-session -t autopwn-live
```

ثم افتح طرفية جديدة و `bash run.sh`
