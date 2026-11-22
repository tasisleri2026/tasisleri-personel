# Taş İşleri Personel ve Mesai Takip Programı — Cloudflare sürümü

- `public/` — programın kendisi (index.html), köprü (cf.js), simgeler, manifest
- `src/worker.js` — sunucu: kullanıcı adı/şifre ile giriş, yetkiler, veritabanı (D1),
  her 15 dakikada trafik, saat başı hava/kur/altın güncellemesi
- `wrangler.jsonc` — Cloudflare ayarları. Kurulumda yalnız `database_id` değiştirilir.

Gizli değerler (`KURUCU`, `TOMTOM_KEY`) bu depoya yazılmaz; Cloudflare panelinde
*Settings → Variables and Secrets* altına "Secret" olarak girilir.

## Yetkiler (sunucuda uygulanır)
| Kim | Görür | Kaydeder |
| --- | --- | --- |
| Giriş yapmamış | yalnız giriş ekranı | — |
| İşçi, usta başı | kendi ekranları, yoklama, plan, talep, duyuru | yoklama, plan, talep, günlük not, duyuru |
| Sınırlı yönetici (maaş/bordro yetkili) | + ücret, puantaj, ödeme | + maaş/bordro işaretleri |
| Yönetici | her şey (kullanıcı hesapları hariç) | her şey (rol/unvan/yetki hariç) |
| Genel Müdür | her şey | her şey; rol, unvan, yetki atama |
| Hesap yetkilisi (Genel Müdür, Satış ve Planlama Yöneticisi) | + kullanıcı hesapları | kullanıcı adı açma, şifre oluşturma |
| Kişisel bilgi yetkilisi (Genel Müdür, Satış ve Planlama Yöneticisi) | + kimlik no, uyruk, doğum tarihi, adres | bu bilgileri girme |

Giriş denemesi sınırı: aynı kullanıcı adına 15 dakikada 8, aynı ağdan 20 hatalı deneme.

Program güncellendiğinde yalnız `public/index.html` değiştirilir; GitHub'a yüklenince Cloudflare kendiliğinden yeniden yayınlar.
