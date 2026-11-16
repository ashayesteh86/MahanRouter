# سند معماری Mahan Router (جایگزین پیشرفته میکروتیک)

> نسخه اصلی سند معماری، 2026-11-16. تصمیم‌های بعد از بازبینی در انتهای سند آمده است.

## ۱. هدف و چشم‌انداز
ساخت یک سیستم‌عامل روتر مبتنی بر لینوکس که روی سخت‌افزار آماده (x86 و ARM) نصب شود، در فاز اول امکانات پایه میکروتیک را پوشش دهد و در فازهای بعدی با IPS/IDS، WAF، مدیریت متمرکز و تحلیل ترافیک از آن پیشی بگیرد. تمرکز صرفاً روی نرم‌افزار است؛ سخت‌افزار از بازار تأمین می‌شود (مینی‌پی‌سی‌های x86 با چند پورت اینترنت، بوردهای ARM، یا ماشین مجازی).

## ۲. اصول طراحی
- پایه: Debian مینیمال با کرنل LTS.
- جداسازی لایه‌ها: Data Plane (کرنل، nftables، XDP) / Control Plane (سرویس مدیریت با Go) / Management Plane (API و پنل وب).
- کانفیگ اعلانی (Declarative): کل تنظیمات در یک فایل YAML با نسخه‌بندی Git، امکان commit، diff و rollback.
- API-first: هر کاری که از پنل می‌شود، از REST و gRPC هم باید بشود؛ CLI روی همان API ساخته می‌شود.
- امنیت پیش‌فرض: Secure Boot در صورت امکان، فایل‌سیستم فقط‌خواندنی برای سیستم، به‌روزرسانی اتمیک با دو پارتیشن (A/B).
- چندمستأجری سبک: پشتیبانی از VRF و namespace برای جداسازی مشتریان یا شعب.

## ۳. معماری اجزا
**لایه داده:** nftables برای فایروال، NAT و mangle؛ XDP/eBPF برای DDoS mitigation، rate limiting و شمارنده‌های سریع؛ tc و CAKE/fq_codel برای QoS؛ در آینده VPP یا DPDK برای ۱۰ گیگ به بالا.

**لایه کنترل:** FRRouting (BGP، OSPF، RIP، IS-IS، BFD)؛ WireGuard، strongSwan، OpenVPN، و L2TP/PPTP فقط برای سازگاری؛ Kea DHCP، Unbound، chrony، accel-ppp برای PPPoE سرور و Hotspot؛ سرویس مرکزی Go به نام core-agent (در کد: `mahan-agent`).

**لایه مدیریت:** API Gateway با Go (REST + gRPC + WebSocket)؛ پنل وب React؛ CLI شبیه میکروتیک/Cisco؛ احراز هویت محلی، RADIUS/TACACS+، LDAP/AD، MFA، RBAC؛ Prometheus، syslog، NetFlow/IPFIX، SNMP.

## ۴. فازبندی
**فاز ۱ — برابری با میکروتیک (MVP):**
- اینترفیس‌ها (Ethernet، VLAN، Bridge، Bonding، PPPoE client)
- روتینگ استاتیک، OSPF و BGP
- NAT
- فایروال با address list، conntrack و شمارنده
- VPN: WireGuard، IPsec و OpenVPN
- DHCP، DNS و NTP
- QoS ساده
- پنل وب، CLI و API
- بکاپ/ریستور و آپدیت

**فاز ۲ — امنیت پیشرفته:**
- Suricata inline با رول‌ست ET Open
- WAF (reverse proxy + Coraza + OWASP CRS) با مدیریت کامل گواهی:
  - ACME با lego، چالش‌های HTTP-01 و DNS-01 و wildcard
  - تمدید خودکار و هشدار شکست تمدید
  - HSTS، HTTP/2 و HTTP/3
  - CA داخلی
  - کلیدهای رمزشده روی دیسک
- DNS filtering
- GeoIP و threat feeds
- هشدار به تلگرام، ایمیل و Webhook

**فاز ۳ — تمایز رقابتی:**
- کنترلر مرکزی با zero-touch provisioning
- SD-WAN
- DPI
- ZTNA
- دستیار هوش مصنوعی
- Marketplace افزونه‌ها (کانتینر)

## ۵. فناوری
- Go برای سرویس‌ها؛ Rust یا C با eBPF برای بخش‌های حساس
- YAML در Git + SQLite
- React + TypeScript + Tailwind + ECharts
- ساخت ایمیج با mkosi یا debos (ISO، qcow2، OVA، SD)
- تست با containerlab/GNS3 و Robot Framework

## ۶. سخت‌افزار تست
- مینی‌پی‌سی N100/N305 با ۴ تا ۶ پورت 2.5G
- NanoPi R6S یا Banana Pi R4
- VM روی Proxmox یا VMware

### دستگاه‌های EOL برای ریسایکل (نسخه سبک روی OpenWrt)
معیار:
- رادیو Qualcomm Atheros یا MediaTek
- حداقل ۱۲۸MB رم و ۱۶MB فلش
- پشتیبانی موجود در OpenWrt

هر مدل قبل از خرید انبوه باید روی جدول سخت‌افزار OpenWrt و با یک نمونه فیزیکی تأیید شود.

| سازنده | مدل | نوع | رادیو | رم | OpenWrt | روش فلش | نکته |
|---|---|---|---|---|---|---|---|
| Cisco Meraki | MR18 | AP داخلی | Qualcomm ac wave1 | 128MB | بله | UART | ارزان و فراوان |
| Cisco Meraki | MR24 | AP داخلی | Atheros n | 128MB | بله | UART | فقط Wi-Fi 4 |
| Cisco Meraki | MR33 | AP داخلی | IPQ4029 ac wave2 | 256MB | بله | UART + دور زدن بوت‌لودر | بهترین قیمت/کارایی |
| Cisco Meraki | MR42 | AP داخلی | IPQ8068 ac wave2 | 512MB | بله | UART | قدرتمند |
| Cisco Meraki | MR52 | AP داخلی | IPQ8068 ac wave2 | 512MB | بله | UART | دو پورت |
| Cisco Meraki | MR74 | AP بیرونی | IPQ4029 | 256MB | بله | UART | outdoor |
| Cisco Meraki | MX64 / MX65 | روتر | — | 1GB | بله | UART | هدف عالی برای نسخه روتر |
| Cisco Meraki | MX64W / MX65W | روتر + Wi-Fi | Qualcomm | 1GB | جزئی | UART | وایرلس نیاز به بررسی |
| Cisco Aironet | 1140…3700 | AP | اختصاصی | — | خیر | — | هدف نگیرید |
| Ubiquiti | UAP-AC-Lite/LR/Pro/Mesh | AP | Qualcomm ac wave2 | 128MB | بله | SSH/TFTP | ساده‌ترین فلش |
| Ubiquiti | UniFi 6 Lite/LR | AP Wi-Fi 6 | MT7621 + MT7915 | 256MB | بله | SSH | Wi-Fi 6 ارزان |
| Aruba | AP-105 | AP | Atheros n | 128MB | بله | UART | بسیار ارزان |
| Aruba | AP-303H / 303 | AP | IPQ4029 | 512MB | بله | UART | 303H چند پورت |
| Aruba | AP-365 / 367 | AP بیرونی | IPQ4019 | 512MB | بله | UART | outdoor |
| Ruckus | R310 / R500 / R600 | AP | Qualcomm | 256MB | بله | UART/TFTP | دست‌دوم فراوان |
| MikroTik | hAP ac2/ac3, RB750Gr3, RB4011 | روتر | Qualcomm/MediaTek | 256MB–1GB | بله | Netinstall | لایسنس RouterOS از دست می‌رود |
| Netgear / TP-Link | R7800, WAX206, Archer C7, EAP225 | روتر/AP | Qualcomm/MediaTek | 128–512MB | بله | وب/TFTP | پشتیبان ارزان |

نکات اجرایی:
- ایستگاه فلش Meraki با USB-UART و اسکریپت خودکار؛ زمان فلش هر دستگاه کمتر از ۱۰ دقیقه.
- دستگاه‌های ۱۲۸MB فقط نسخه سبک را می‌گیرند؛ WAF و Suricata فقط روی x86 و دستگاه‌های ۵۱۲MB به بالا.
- برای هر مدل یک پروفایل سخت‌افزاری تعریف شود: پورت‌ها، LEDها، دکمه ریست و رادیوها.
- برند خودمان با ضمانت محدود. باید به خریدار اعلام شود که فرم‌ور اصلی قابل بازگشت نیست.

## ۷. برنامه اجرایی
| زمان | کار |
|---|---|
| ماه ۱–۲ | ایمیج پایه، core-agent، مدل کانفیگ، اینترفیس‌ها، NAT و فایروال |
| ماه ۳–۴ | FRR، VPNها، DHCP/DNS، پنل وب نسخه اول، CLI |
| ماه ۵ | پایداری، تست کارایی، آپدیت A/B، مستندات، نسخه آزمایشی داخلی |
| ماه ۶–۸ | Suricata، WAF و گزارش امنیتی |
| بعد از آن | کنترلر مرکزی و SD-WAN |

**مدل انتشار:**
- هسته اوپن‌سورس با GPLv2 برای اجزای کرنل و eBPF، و Apache 2.0 برای سرویس‌های Go.
- درآمد از پشتیبانی، کنترلر ابری، رول‌ست‌ها و دستگاه‌های ریسایکل‌شده.
- دو توزیع: Debian برای x86 و ARM قوی، OpenWrt برای دستگاه‌های سبک.
- روی سخت‌افزار میکروتیک دو مسیر هست: کانتینر روی RouterOS 7، یا جایگزینی کامل RouterOS با Netinstall.
- ابزار تبدیل خروجی `export` میکروتیک به فرمت ما.

## ۸. ریسک‌ها
- کارایی: nftables تا چند گیگابیت کافی است؛ بالاتر از آن XDP یا VPP لازم می‌شود.
- لایسنس: اگر کد بسته لازم شد، ارتباط با اجزای GPL فقط از طریق پروسس و API جدا باشد.
- برند: نام فعلی Mahan Router است. «MikroTik» فقط در توضیح سازگاری بیاید، نه در نام یا تبلیغ محصول.

## تصمیم‌های بعد از بازبینی (2026-11-16)
1. پایه Debian است، نه فورک VyOS. VyOS مدل کانفیگ خودش را دارد که با core-agent در تضاد است.
2. اولویت ماه اول با مدل کانفیگ و چرخه commit / confirm / rollback است؛ پنل بعداً روی همان API ساخته می‌شود.
3. در فاز ۱، WireGuard و IPsec اول می‌آیند؛ OpenVPN و L2TP به فاز ۱.۵ منتقل شد.
4. نسخه OpenWrt بعد از فاز ۱ ساخته می‌شود. یا agent سبک می‌خواهد، یا مترجم کانفیگ به UCI.
