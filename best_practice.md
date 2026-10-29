# Documentación de Best Practices de Seguridad

**Asignatura:** Programación Android  
**Evaluación:** Actividad 2.5 - Manejo de elementos de seguridad  
**Módulo:** Implementación de Buenas Prácticas (Best Practices)

Para el desarrollo e investigación de este apartado se utilizó Asistencia de Inteligencia Artificial como herramienta de consulta y guía de aprendizaje, documentando los prompts utilizados y la implementación técnica realizada en la aplicación Android.

---

## 1. Cifrado de Datos Sensibles (Data at Rest)

### Prompt Utilizado para Consulta y Orientación
> *"Estoy trabajando en una App de Android en Java que usa mapas y necesito guardar las coordenadas del usuario de forma local. ¿Por qué no es recomendable usar SharedPreferences convencional y qué alternativa segura de Jetpack me recomiendas investigar? Dame una orientación teórica y un ejemplo conceptual de la diferencia."*

### Investigación Teórica
Los archivos `SharedPreferences` convencionales guardan la información en texto plano en archivos XML internos del dispositivo. En dispositivos con acceso root o mediante copias de seguridad (`adb backup`), un atacante puede extraer y leer esta información fácilmente. La mejor práctica recomendada por Android Security y OWASP exige implementar `EncryptedSharedPreferences` (Librería `Jetpack Security`), la cual utiliza una clave maestra (`MasterKey`) protegida en el hardware del dispositivo (`Android Keystore`) y cifrado AES-256 para proteger claves y valores.

### Implementación en Código (Java)
- **Antes (Práctica insegura):**
  ```java
  SharedPreferences prefs = getSharedPreferences("MapPrefs", MODE_PRIVATE);
  prefs.edit().putString("last_location", lat + "," + lng).apply();