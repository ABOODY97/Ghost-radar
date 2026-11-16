<div dir="ltr" align="center">

```text
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
          R  A  D  A  R   V 3.0              
           -= FROM ABOODY =-                 
```

</div>

<div dir="rtl">

# أداة Ghost Radar

## 🌟 نبذة عن الأداة
أداة **Ghost Radar** هي أداة فحص شبكات واستطلاع (Reconnaissance) متقدمة وسريعة تعتمد على Python، صُممت ببنية معيارية (Modular Architecture) تجمع بين سهولة التطوير، التشفير القوي للبيانات، ووضع التخفي (Ghost Mode) لحماية خصوصيتك أثناء الفحص.

---

## ✨ المميزات الرئيسية
* **دعم كامل للغة العربية في التيرمنال! 🇸🇦:** عرض سليم للأحرف العربية من اليمين لليسار عبر مكتبات `arabic_reshaper` و `python-bidi`، مع دعم التبديل الفوري بين **العربية، الإنجليزية، والتركية**.
* **وضع الشبح (Ghost Mode):** تمويه حركة الشبكة عبر عناوين MAC عشوائية، تأخير زمني موزع طبيعياً (Poisson Delay)، إخفاء اسم العملية، ودعم تمرير الاستعلامات عبر **Tor / SOCKS5** أو عزلها كلياً.
* **تشفير البيانات والخزنة (AES-256-GCM Vault):** جميع السجلات والتقارير المحفوظة (JSON / HTML) تُشفّر تلقائياً بمفتاح مرتبط ببصمة الجهاز عبر `HMAC` لضمان عدم كشف أي عناوين IP أو بيانات شبكة كنص صريح.
* **فحص الشبكة المحلية (ARP Scanner):** اكتشاف الأجهزة المتصلة، عناوين MAC، الشركات المصنّعة، وتخمين نظام التشغيل عبر بصمة TTL، مع تنبيه فوري عند ظهور أجهزة جديدة أو اختفاء أجهزة سابقة.
* **استطلاع المواقع والسيرفرات (Web Recon):** فحص الموقع الجغرافي، مزود الخدمة (ISP)، الترويسات الأمنية المفقودة، شهادات SSL/TLS، سجلات DNS (مع دعم DoH عبر البروكسي)، واكتشاف النطاقات الفرعية عبر Certificate Transparency.
* **فحص المنافذ العميق والثغرات (Deep Port & CVE Scanner):** مسح SYN خفي، جلب بصمات الخدمات (Banner Grabbing)، والتحقق التلقائي من الثغرات المعروفة عبر قاعدة **NVD** الرسمية.

---

## ⚠️ إخلاء المسؤولية
> **تنويه هام:** تم تصميم هذه الأداة للأغراض التعليمية واختبار الاختراق الأخلاقي وفحص أمن الشبكات الخاصة فقط. يُرجى استخدامها حصرياً على الشبكات والأنظمة التي تمتلك تصريحاً صريحاً لاختبارها.

---

## 🛠️ المتطلبات والتثبيت

1. قم بتثبيت المكتبات المطلوبة عبر أحد الأوامر التالية:
```bash
pip install -r requirements.txt
# أو في ويندوز:
py -m pip install -r requirements.txt
python -m pip install -r requirements.txt
```

2. قم بتشغيل الأداة (يُفضل بصلاحيات المسؤول/Root لضمان عمل حزم Scapy وفحص ARP/SYN بشكل صحيح):
```bash
sudo python3 Ghost_Radar.py        # Linux / macOS
py Ghost_Radar.py                  # Windows (بصلاحيات Administrator)
```

---

## 📂 هيكل المشروع (Project Structure)

```text
Ghost_Radar.py            الملف الأساسي: القائمة (class GhostRadar) + SESSION_DATA
core/
  ui.py                   الألوان (GREEN/RED/...) + sanitize_text + fix_ar
modules/
  language_ar.py          نصوص اللغة العربية الاحتياطية
  i18n.py                 اختيار اللغة والترجمة _t()
  vault.py                تشفير/فك تشفير كل ما يُكتب على القرص (AES-256-GCM)
  validators.py           التحقق من المدخلات (دومين/CIDR/منافذ)
  privacy.py              وضع الشبح + سياسة GHOST_PROXY / GHOST_NO_EXTERNAL
  network_utils.py        IP/شبكة محلية، DNS عبر البروكسي، مسح ARP
  history.py              سجل الفحص السابق (أجهزة جديدة/مختفية)
  recon.py                بصمات TTL، شهادات SSL، سجلات DNS، نطاقات فرعية
  scanner.py              مسح الشبكة + المنافذ + CVEs + استطلاع المواقع
  reporter.py             تقرير HTML/JSON
  vaultfile.py            فك تشفير تقارير HTML/JSON وسجل الفحص خارج البرنامج
tools/
  check_main.py           يتأكد أن كل الميزات تصل للملف الأساسي (لا استيراد ميت)
  verify_refactor.py      يقارن الأسماء والنصوص مع النسخة الأصلية
  smoke_imports.py        استيراد كل الوحدات بسرعة
  smoke_run.py            تشغيل القائمة (--net = فحص موقع حقيقي + تبديل اللغة)
  test_fixes.py           اختبارات اللغات الثلاث وفحص المواقع والتنظيف
  test_unseal.py          اختبار فك التشفير (يقارن الناتج بالأصل)
  unseal_report.py        أداة فك تشفير التقرير HTML/JSON والسجل من الطرفية
```

---

## 🧩 آلية العمل والحالة المشتركة

### 1. تجميع الميزات (Feature Aggregation)
يعتمد `Ghost_Radar.py` على جدول واحد `MODULE_FEATURES` يحدد كل وحدة والأسماء التي تمنحها للملف الأساسي، وتقوم حلقة واحدة بتجميعها:
```python
for _module_name, _names in MODULE_FEATURES.items():
    _module = sys.modules[_module_name]
    for _name in _names:
        globals()[_name] = getattr(_module, _name)
```
> **لإضافة ميزة جديدة:** ضعها في ملفها المناسب داخل `modules/`، ثم أضف اسمها إلى `MODULE_FEATURES` فقط دون الحاجة لتعديل بقية الملف.

### 2. الحالة المشتركة للغات (Shared State)
نسخ قيمة إلى `globals()` ينسخ *القيمة* لا *المرجع*؛ لذلك توجد اللغة الحيّة في كائن واحد `modules.i18n.state`، ويقرأ الملف الأساسي `CURRENT_LANG` و `LANGUAGES` عبر `__getattr__` من هذا الكائن مباشرة لضمان تحديث اللغة في كافة الوحدات فوراً.

---

## 🔐 فك تشفير التقارير والسجل (Unsealing Reports)

جميع التقارير والسجلات مشفّرة بخوارزمية **AES-256-GCM** باستخدام مفتاح الخزنة المحفوظ في:
* **Linux / macOS:** `~/.ghost_radar/vault.key`
* **Windows:** `C:\Users\<اسمك>\.ghost_radar\vault.key`

### من الطرفية (CLI):
```bash
# فك تشفير ملف واحد
py tools/unseal_report.py ghost_radar_report_20261115_101500.html

# فك تشفير جميع الملفات المشفّرة في المجلد الحالي
py tools/unseal_report.py

# استخدام مفتاح من نسخة احتياطية وتحديد اسم ملف الناتج
py tools/unseal_report.py report.html --key D:\backup\vault.key -o report_plain.html
```
يُحفظ الناتج بجانب الملف الأصلي باللاحقة `_decrypted.html` أو `_decrypted.json`.

### من داخل كود Python:
```python
from modules.vaultfile import unseal_file, unseal_json, unseal_html_report

unseal_file('ghost_radar_report_20261115_101500.html')   # -> مسار الملف المفكوك
history = unseal_json('ghost_radar_history.json')        # -> dict
html = unseal_html_report(open('report.html', encoding='utf-8').read())
```

### عبر المتصفح مباشرة:
عند فتح ملف التقرير `HTML` المشفّر في المتصفح، يمكنك لصق **أول 32 بايت من المفتاح** (بترميز Base64 من ملف `vault.key`) لعرض التقرير داخل إطار معزول (`sandboxed iframe`) بأمان تام.

> **ملاحظة أمنية:** المفتاح مربوط بالجهاز عبر `HMAC`؛ عند نقل التقرير إلى جهاز آخر ستحتاج إلى نسخ ملف `vault.key` الأصلي وتمريره عبر `--key`.

---

## ⚙️ متغيرات البيئة (Environment Variables)

| المتغير | الوظيفة |
| :--- | :--- |
| `GHOST_NO_EXTERNAL=1` | منع أي اتصال خارجي (وضع العزل الكامل) |
| `GHOST_PROXY=socks5h://127.0.0.1:9050` | تمرير جميع الاستعلامات الخارجية عبر Tor / بروكسي |
| `GHOST_NO_BANNER=1` | منع جلب بصمات الخدمات (Banner Grabbing) |
| `GHOST_ALLOW_DIRECT_TLS=1` | السماح بفحص شهادة SSL مباشر في وضع الشبح |
| `GHOST_PLAINTEXT_FILES=1` | السماح بحفظ التقارير بدون تشفير عند غياب مكتبة `cryptography` |

---

## 🌐 المصادر الخارجية المستخدمة في فحص المواقع

| الخدمة | الغرض | ملاحظة |
| :--- | :--- | :--- |
| `ip-api.com` / `ip-api.io` | تحديد الدولة، المدينة، ومزود الخدمة (ISP) | مجاني بدون مفتاح (محدود بعدد طلبات في الدقيقة) |
| `crt.sh` | اكتشاف النطاقات الفرعية (Certificate Transparency) | قد يعيد خطأ `502` أحياناً عند الضغط على الخادم |
| `services.nvd.nist.gov` | البحث عن الثغرات المعروفة (CVEs) | قاعدة بيانات الثغرات الرسمية |
| `certifi` | التحقق من شهادات SSL | ضروري على ويندوز لتحديث الجذور الموثوقة |

---

## 🧪 فحص سريع بعد أي تعديل (Test Suite)

للتأكد من سلامة الوحدات، الاستيرادات، والتشفير بعد أي تطوير جديد:
```bash
py tools/smoke_imports.py
py tools/check_main.py
py tools/verify_refactor.py
py tools/test_fixes.py
py tools/smoke_run.py --net
py tools/test_unseal.py
```

</div>