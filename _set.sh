#!/bin/bash
echo "=== Настройка прав для LegacyCoin + Web ==="

# Создаём папку, если её нет
mkdir -p /home/coin/.legacycoin

# Основные права
chown coin:www-data /home/coin/.legacycoin/.cookie 2>/dev/null || true
chmod 640 /home/coin/.legacycoin/.cookie 2>/dev/null || true

chown -R coin:www-data /home/coin/.legacycoin
chmod -R 750 /home/coin/.legacycoin

# Права на бинарники (если нужно)
if [ -f "/home/coin/LegacyCore/legacycoind" ]; then
    chown coin:coin /home/coin/LegacyCore/legacycoind
    chmod 755 /home/coin/LegacyCore/legacycoind
fi

if [ -f "/home/coin/LegacyCore/legacycoin-cli" ]; then
    chown coin:coin /home/coin/LegacyCore/legacycoin-cli
    chmod 755 /home/coin/LegacyCore/legacycoin-cli
fi

echo " Права настроены"
echo "Cookie:"
ls -l /home/coin/.legacycoin/.cookie
echo ""
echo "Папка .legacycoin:"
ls -ld /home/coin/.legacycoin

