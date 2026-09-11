# FileGuard

FileGuard, Android cihazlar üzerinde dosyaların statik güvenlik analizini gerçekleştirmek için geliştirilen bir Android uygulamasıdır.

Uygulama seçilen dosyayı cihaz üzerinde analiz ederek dosya türü, MIME type, SHA-256 hash ve çeşitli yapısal güvenlik göstergelerini incelemeyi amaçlar.

## Özellikler

- Android sistem dosya seçicisi
- Dosya adı ve boyut analizi
- MIME type analizi
- Dosya uzantısı kontrolü
- Magic byte / dosya header kontrolü
- SHA-256 hash hesaplama
- APK yapısal analizi
- AndroidManifest analizi
- Permission analizi
- Activity, Service, Receiver ve Provider analizi
- Exported component tespiti
- DEX string/pattern analizi
- Native library tespiti
- Heuristic risk değerlendirmesi
- 0-100 arası risk skoru
- Güvenli / Düşük Risk / Şüpheli / Yüksek Risk sınıflandırması
- Cihaz üzerinde statik analiz

## Teknolojiler

- Kotlin
- Android Studio
- Jetpack Compose
- Material 3
- Kotlin Coroutines
- Android Storage Access Framework

## Analiz Mantığı

FileGuard bir dosyayı çalıştırmaz.

Analiz işlemi statik olarak gerçekleştirilir:

```text
Dosya
  ↓
Metadata
  ↓
SHA-256
  ↓
Dosya türü
  ↓
Dosya yapısı
  ↓
APK ise Manifest
  ↓
Permissions
  ↓
Components
  ↓
DEX
  ↓
Native Libraries
  ↓
Risk değerlendirmesi
