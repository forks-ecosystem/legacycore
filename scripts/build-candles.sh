#!/bin/bash
for tf in 1m 5m 15m 30m 1h 4h 1d 1w; do
  php -r "
    \$_GET = ['tf'=>'$tf','pair'=>'all','dry'=>'0'];
    include '/var/www/html/forkex-my/hollaex/tb/candles/aggregate.php';
  " 2>&1
done
