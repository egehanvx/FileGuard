# FileGuard

<div align="center">

**Android üzerinde çalışan statik dosya güvenlik ve risk analiz aracı**

Dosyaları çalıştırmadan inceleyen, APK'ları statik olarak analiz eden ve elde edilen bulgular üzerinden heuristic risk değerlendirmesi oluşturan Android uygulaması.

<br>

![Android](https://img.shields.io/badge/Android-7.0%2B-3DDC84?style=flat-square&logo=android&logoColor=white)
![Kotlin](https://img.shields.io/badge/Kotlin-2.x-7F52FF?style=flat-square&logo=kotlin&logoColor=white)
![Jetpack Compose](https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285F4?style=flat-square&logo=jetpackcompose&logoColor=white)
![Status](https://img.shields.io/badge/Status-In%20Development-orange?style=flat-square)

</div>

---

## 📸 Uygulama

<div align="center">

<table>
<tr>
<td align="center"><b>Ana Ekran</b></td>
<td align="center"><b>Dosya Analizi</b></td>
</tr>

<tr>
<td>
<img src="./screenshots/home.png" width="300">
</td>

<td>
<img src="./screenshots/file-analysis.png" width="300">
</td>
</tr>

<tr>
<td align="center"><b>APK Statik Analizi</b></td>
<td align="center"><b>Risk Değerlendirmesi</b></td>
</tr>

<tr>
<td>
<img src="./screenshots/apk-analysis.png" width="300">
</td>

<td>
<img src="./screenshots/risk-result.png" width="300">
</td>
</tr>
</table>

</div>

---

## 🛡️ Proje Hakkında

**FileGuard**, Android cihazlar üzerinde dosyaların statik güvenlik analizini gerçekleştirmek amacıyla geliştirilen bir uygulamadır.

Uygulama kullanıcı tarafından seçilen dosyayı çalıştırmadan analiz eder ve dosyanın güvenlik açısından dikkat edilmesi gereken özelliklerini ortaya çıkarmaya çalışır.

Özellikle APK dosyaları için daha kapsamlı analiz uygulanır.

Analiz sonucunda elde edilen bulgular bir heuristic risk değerlendirme motoruna aktarılır ve dosyaya bir risk skoru oluşturulur.

> **Not:** FileGuard ticari bir antivirüs değildir ve mevcut sürümde kesin malware tespiti iddiasında bulunmaz. Sonuçlar statik analiz ve heuristic risk değerlendirmesine dayanır.

---

# ✨ Özellikler

## 📂 Dosya Analizi

Android'in sistem dosya seçicisi kullanılarak cihazdaki farklı dosyalar seçilebilir.

Desteklenen örnekler:

- APK
- ZIP
- PDF
- TXT
- JSON
- PNG
- JPEG
- diğer yaygın dosya türleri

Seçilen dosyanın:

- dosya adı
- dosya boyutu
- uzantısı
- MIME type
- SHA-256 hash'i
- gerçek dosya formatı

tespit edilir.

---

## 🔐 SHA-256

Dosyanın SHA-256 hash değeri cihaz üzerinde hesaplanır.

Büyük dosyalarda dosyanın tamamı tek seferde belleğe alınmaz. Dosya stream üzerinden parça parça okunur.

```text
Dosya
  ↓
InputStream
  ↓
Buffer
  ↓
SHA-256
  ↓
Hash
