## 🇬🇧 English Guide

## 🔍 Google SQL Injection Dork Scanner
A Python script that detects websites potentially vulnerable to SQL Injection using Google dorks.
It opens a browser in minimized mode and uses undetected_chromedriver to bypass bot detection.

## 🚀 Features
Performs Google searches using dorks like inurl:php?=id.

Filters URLs that end in a numeric parameter.

Tests for SQL Injection by appending ' to URLs.

Checks for known SQL error messages in page sources.

Saves vulnerable sites to sqli_sites.txt.

Tracks scan progress in progress.json to allow resuming after interruptions.

Asks the user how many vulnerable sites to find.

Optionally continues scanning after the target is reached.

## 📦 Installation
Install required dependencies:

`pip install selenium undetected-chromedriver`
Google Chrome must also be installed on your system.

## ⚙️ Usage

Run the script:

`python scanner.py`
The program will ask how many vulnerable sites you want.

It will open a minimized browser window and begin scanning via Google.

Discovered vulnerable URLs are added to sqli_sites.txt.

You can close and reopen the program at any time — it will continue from where it left off.

🇹🇷 Türkçe Kullanım







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
