# نصب Mahan Router روی VMware (ESXi / Workstation)

## ساخت ماشین مجازی
| تنظیم | مقدار |
|---|---|
| Guest OS | Linux → Debian GNU/Linux 12 (64-bit) |
| CPU / RAM | حداقل ۲ vCPU و ۱ گیگ رم؛ برای FRR و ترافیک زیاد ۲ گیگ |
| دیسک | ۸ گیگ کافی است (SCSI یا SATA) |
| Firmware | BIOS یا EFI؛ هر دو پشتیبانی می‌شود. Secure Boot را فعلاً خاموش کنید |
| کارت شبکه | حداقل ۲ کارت از نوع **VMXNET3** (E1000 هم کار می‌کند) |
| CD/DVD | فایل ISO با تیک Connect at power on |

ترتیب کارت‌ها مهم است:
- **Network adapter 1 → ether1 = WAN.** کلاینت DHCP است. آن را به port group سمت اینترنت یا شبکه‌ی بالادست وصل کنید.
- **Network adapter 2 به بعد → ether2، ether3 و … = LAN.** این پورت‌ها در bridge-lan با آدرس 192.168.88.1/24 هستند و DHCP Server، DNS و NAT دارند.

اگر LAN را به یک port group با VLAN یا با چند کلاینت وصل می‌کنید، روی ESXi این‌ها را برای آن port group روی Accept بگذارید تا bridge درست کار کند:
- Promiscuous mode
- MAC address changes
- Forged transmits

## بوت
منوی ISO سه گزینه دارد:
1. **live**: بدون نصب اجرا می‌شود و تغییرات با ریبوت از بین می‌رود. برای امتحان مناسب است.
2. **Install to disk**: نصاب روی کنسول باز می‌شود. دیسک را انتخاب کنید و `YES` تایپ کنید. بعد ISO را جدا کنید و ریبوت کنید.
3. **self-test**: گزارش سلامت را روی پورت سریال چاپ می‌کند. برای عیب‌یابی است.

نصاب را از داخل حالت live هم می‌شود اجرا کرد: دستور `mahan-install`. هر کانفیگی که در حالت live commit کرده باشید روی دیسک منتقل می‌شود.

## پنل وب
از یک کامپیوتر در شبکه‌ی LAN (پورت ether2 به بعد) آدرس **https://192.168.88.1** را باز کنید:
- **ورود:** با `admin` و رمز `mahan`. پنل از شما می‌خواهد رمز را عوض کنید.
- **هشدار گواهی:** مرورگر یک بار هشدار می‌دهد، چون گواهی self-signed است. آن را بپذیرید.
- **ذخیره‌ی تغییرات:** هر تغییری که در فرم‌ها می‌دهید اول فقط ذخیره می‌شود. روی روتر وقتی اعمال می‌شود که در صفحه‌ی «تغییرات و تاریخچه» دکمه‌ی «اعمال» را بزنید.
- **حالت امن:** بعد از اعمال، در نوار بالا «تأیید و نگه داشتن» را بزنید. اگر تا ۱۲۰ ثانیه تأیید نکنید، روتر خودکار به کانفیگ قبلی برمی‌گردد.

## ورود و کار اولیه
- **ورود:** کاربر `root` با رمز `mahan`. فوراً با `passwd` عوضش کنید.
- **دسترسی SSH:** فقط از سمت LAN. فایروال پیش‌فرض، مثل میکروتیک، ورودی از WAN را می‌بندد.

دستورهای اصلی:
```bash
mrctl show                 # کانفیگ فعلی
mrctl edit                 # ویرایش کانفیگ کاندید با vi
mrctl diff
mrctl commit -m "..." --confirm 120   # اگر تا ۱۲۰ ثانیه confirm نزنید، خودکار برمی‌گردد
mrctl confirm
mrctl history
mrctl rollback HEAD~1
mahan-selftest             # گزارش وضعیت سرویس‌ها
```
نمونه‌ی کانفیگ کامل (VLAN، PPPoE، WireGuard، OSPF و port forward) در `examples/branch-office.yaml` مخزن است.

### باز کردن SSH از سمت WAN (مثلاً برای مدیریت از شبکه‌ی اداره)
در `mrctl edit`، قبل از rule «drop all not coming from LAN» این را اضافه کنید:
```yaml
    - { chain: input, action: accept, in_interface_list: WAN, src_address: 192.168.1.0/24, protocol: tcp, dst_port: "22", comment: "SSH from office" }
```
بعد `mrctl commit --confirm 120` بزنید. اگر هنوز وصل هستید، `mrctl confirm` را اجرا کنید.

## محدودیت‌های این نسخه
در این نسخه موارد زیر هنوز وجود ندارد و در `docs/STATUS.md` آمده است:
- پنل وب
- IPsec و OpenVPN
- صف برای هر IP
- کاربران و نقش‌ها
- به‌روزرسانی A/B

فایل‌سیستم نصب‌شده هم هنوز read-only نیست.
