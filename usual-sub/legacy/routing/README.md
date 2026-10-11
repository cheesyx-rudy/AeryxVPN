# LIKVID VPN — Happ routing

`LIKVID-RU-WHITELIST.JSON` — единственный исходный файл профиля маршрутизации.
При сборке подписки `proxy_parser.py` обновляет `LastUpdated`, генерирует
`LIKVID-RU-WHITELIST.DEEPLINK` и вставляет ту же deeplink-ссылку в `proxies.txt`.

## Логика

- По умолчанию трафик идёт через VPN (`GlobalProxy: true`).
- `geosite:whitelist` и `geoip:whitelist` направляются напрямую.
- `geosite:category-ru` и `geoip:direct` направляются напрямую.
- Частные адреса направляются напрямую.
- `geosite:win-spy`, `geosite:torrent` и `geosite:category-ads` блокируются.
- `UseChunkFiles: true` включён для уменьшения использования памяти, что особенно важно на iOS.

## Обновление

Профиль не загружается Happ из отдельного URL JSON. Он передаётся в теле подписки как
`happ://routing/onadd/{base64}`. Когда пользователь обновляет подписку, Happ получает
профиль с тем же именем и обновляет существующую запись. `LastUpdated` меняется при
каждой сборке; Happ самостоятельно ограничивает частоту скачивания геофайлов.

Геофайлы загружаются с постоянных URL, поэтому изменения в upstream-репозиториях будут
доступны после обновления файлов по этим URL и следующего обновления геобаз в Happ.
Само по себе обновление подписки не гарантирует немедленную загрузку новых геофайлов.

Важно: правила и доступность нужно проверить на реальном устройстве iOS и в конкретной
сети. Категории маршрутизации должны существовать в указанных геофайлах.

Источники:
- https://github.com/hydraponique/roscomvpn-routing
- https://github.com/hydraponique/roscomvpn-geoip
- https://github.com/hydraponique/roscomvpn-geosite
- https://www.happ.su/main/ru/dev-docs/routing
