# KASA Kural Taslakları (Rule Templates)

Bu dosya, KASA projesi geliştirilirken karşılaşılan hatalar, beklenmedik durumlar (edge cases) ve canlı gözlemler sonucu çıkarılan kural adaylarını (taslakları) tutar. Buradaki taslaklar onaylandıktan sonra `AGENTS.md` (veya `user_global` kuralları) içerisine kalıcı olarak eklenecektir.

## Taslak 1: Sistemin Kendisinin "Reference Monitor" Olarak Çalışması (Canlı Gözlem)

**Gözlem / Hata Bağlamı:**
Ajan (LLM), çalışma alanı (workspace) dışındaki bir klasöre (`D:\KisiselAsistan\...`) erişerek dosya okumak istedi. Sistem, prompt veya modele bırakmaksızın doğrudan "Permission denied for read_file... Matches default system policy." hatası fırlatarak eylemi deterministik olarak kesti.

**Çıkarılacak Kural Adayı:**
> **"Model Sınır Değildir, Sınır Deterministik Broker'dır"**
> Güvenlik modeli tasarlanırken modelin "bunu yapmamalısın" talimatına asla güvenilmemelidir. Tıpkı geliştirme ortamında ajanın yetki dışı dosyaya erişiminin `Permission denied` ile sertçe kesilmesi gibi, KASA'nın MCP araçları (`filesystem:read`, `profile:write` vb.) da `gate.py` ve izin tablolarında `deny-by-default` (varsayılan reddet) politikasıyla sert bir Reference Monitor duvarına sahip olmalıdır. Bir güvenlik mekanizması ancak ajan o mekanizmayı istese bile aşamadığında "canlı/proved" kabul edilir.

---

## Taslak 2: Karantina Motorunun Senkron Çağrılardan İzole Edilmesi (Önceki Hata Gözlemi)

**Gözlem / Hata Bağlamı:**
Daha önceki testlerde `quarantine.py` içerisine senkron bir HTTP çağrısı (kortex_judge vb.) eklendiğinde testler 4 dakika sürmüş, timeout hataları alınmış ve SQLite iplik güvenliği (thread-safety) sorunları yaşanmıştı.

**Çıkarılacak Kural Adayı:**
> **"Karantina ve Erişim Denetimi Bloklayıcı ve Deterministik Olmalıdır"**
> Hafıza yazım veya araç erişim (gate) sınırlarında ağ tabanlı, dış API'ye bağımlı (LLM tabanlı) veya senkron/gecikmeli yargı mekanizmaları kullanılmamalıdır. Karantina kararları (`_QUARANTINE_PATTERNS` regex gibi) deterministik, %100 yerel ve mili-saniye altında çalışmalıdır. Yapay zekaya dayalı anlamsal güvenlik taramaları canlı erişim sınırında (inline) değil, asenkron tarama (decay/offline scan) adımlarında yapılmalıdır.
