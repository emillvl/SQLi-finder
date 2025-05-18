# 🔍 Google SQL Injection Dork Scanner

Bu Python scripti, Google üzerinden belirlenen dork ile SQL Injection açıklı siteleri tespit eder.  
Tarayıcıyı minimize edilmiş şekilde açar ve bot algılamayı aşmak için `undetected_chromedriver` kullanır.  

## 🚀 Özellikler

- Google'da `inurl:php?=id` dorku ile arama yapar.
- Sonu rakamla biten URL'leri kontrol eder.
- URL'ye `'` ekleyerek SQL Injection testi yapar.
- Sayfa kaynaklarında bilinen SQL hata mesajlarını kontrol eder.
- Açık bulunan siteleri `sqli_sites.txt` dosyasına kaydeder.
- İşlem ilerleyişini `progress.json` dosyasında saklar. Böylece program kapanırsa kaldığı yerden devam eder.
- Kullanıcıdan kaç tane açık site bulunması isteneceğini sorar.
- Hedefe ulaşıldığında devam edip etmeyeceğinizi sorar.

## 📦 Kurulum

Öncelikle gerekli bağımlılıkları yükleyin:

```bash
pip install selenium undetected-chromedriver
Ayrıca Chrome tarayıcınızın yüklü olması gerekmektedir.

## ⚙️ Kullanım
python scanner.py
Program çalıştığında:

Size kaç tane açık site bulması gerektiğini soracak.

Sonrasında minimize edilmiş bir tarayıcı penceresi açıp Google araması yaparak işlemi başlatacak.

sqli_sites.txt dosyasına açık bulunan siteler eklenecek.

Programı dilediğiniz zaman kapatıp açabilir, kaldığı yerden devam ettirebilirsiniz.

## 📂 Çıktı Dosyaları
sqli_sites.txt → SQL Injection açıklı bulunan URL listesi.

progress.json → İşlem ilerleme kaydı (son bakılan sayfa, kontrol edilen URL'ler, başarı sayısı).

## ⚠️ Uyarı
📌 Bu araç sadece eğitim ve kişisel test amaçlıdır.
Yetkisiz sistemlere izinsiz erişim veya test işlemleri suçtur.
Kendi sistemlerinizde veya izinli ortamlar üzerinde kullanmanız önerilir.

## 📌 Ornek run
Minimize edilmiş pencereyle tarayıcı arkaplanda şu şekilde çalışır:

[INFO] Google araması sayfa: 3
[+] SQLi açığı bulundu (2/10): http://example.com/php?id=5
Sayfa 3'te uygun link yok, sonraki sayfaya geçiliyor...
## 📧 İletişim
Herhangi bir sorun, öneri veya geliştirme talebi için bana ulaşabilirsiniz.
PR'lar ve star'lar memnuniyetle karşılanır ⭐️
