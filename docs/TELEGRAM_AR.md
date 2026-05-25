# التشغيل

```bash
cd ~/router
bash run.sh
```

**ملف واحد.** تيليجرام + قائمة.

## الشاشة مقسومة / [SCAN] / autopwn

```bash
bash scripts/fix_tmux.sh
```

ثم **طرفية جديدة** (Ctrl+Shift+T) وليس نفس نافذة tmux:

```bash
cd ~/router && bash run.sh
```

## تحديث الكود

من القائمة: **[9]**  
أو: `git pull` ثم `bash run.sh`

## مسح عميق

تيليجرام → IP → «مسح عميق»  
كل الأدوات + PoCs من `scripts/new_pocs/`
