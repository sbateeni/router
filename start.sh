#!/usr/bin/env bash
# تم دمج كل شيء في run.sh — هذا الملف للتوافق فقط
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run.sh" "$@"
