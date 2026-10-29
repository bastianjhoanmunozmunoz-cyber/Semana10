# Documentación de Best Practices de Seguridad

**Asignatura:** Programación Android  
**Evaluación:** Actividad 2.5 - Manejo de elementos de seguridad  
**Módulo:** Implementación de Buenas Prácticas (Best Practices)  
**Estudiante:** Aaron Urquieta

Para el desarrollo e investigación de este apartado se utilizó Asistencia de Inteligencia Artificial (IA) como herramienta de consulta y guía de aprendizaje, documentando los prompts utilizados, la investigación teórica y la implementación técnica realizada en la aplicación Android.

---

## 1. Cifrado de Datos Sensibles (Data at Rest)

### Prompt Utilizado para Consulta y Orientación
> *"Estoy trabajando en una App de Android en Java que usa mapas y necesito guardar las coordenadas del usuario de forma local. ¿Por qué no es recomendable usar SharedPreferences convencional y qué alternativa segura de Jetpack me recomiendas investigar? Dame una orientación teórica y un ejemplo conceptual de la diferencia."*

### Investigación Teórica
Los archivos `SharedPreferences` convencionales guardan la información en texto plano dentro de archivos XML internos del dispositivo. En dispositivos con acceso root, mediante ataques de extracción física o utilizando copias de seguridad no cifradas (`adb backup`), un atacante puede leer esta información sin restricciones.

La buena práctica recomendada por Android Security y OWASP exige implementar **`EncryptedSharedPreferences`** (librería `androidx.security:security-crypto`). Esta herramienta utiliza el sistema **Android Keystore** para generar y almacenar de forma segura una clave maestra (`MasterKey`) protegida por el hardware del dispositivo. Todas las claves y valores guardados se cifran de extremo a extremo utilizando los algoritmos **AES256_SIV** y **AES256_GCM**.

### ¿Cómo mejora la seguridad de la aplicación?
Garantiza la confidencialidad e integridad de la información local. Aunque un tercero logre extraer el archivo XML de preferencias del almacenamiento del teléfono, solo verá datos cifrados e ilegibles, imposibilitando la ingeniería inversa o el rastreo de ubicaciones privadas.

### Implementación Técnica en Código (Java)

**Antes (Práctica Insegura - Texto Plano):**
```java
// Almacenamiento vulnerable en texto plano
SharedPreferences prefs = getSharedPreferences("MapPrefs", MODE_PRIVATE);
prefs.edit().putString("last_location", lat + "," + lng).apply();
```

**Después (Práctica Segura - Cifrado AES-256):**
```java
// Implementación con Jetpack Security y MasterKey
try {
    MasterKey masterKey = new MasterKey.Builder(this)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build();

    SharedPreferences securePrefs = EncryptedSharedPreferences.create(
            this,
            "secure_map_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    );

    securePrefs.edit().putString("last_location", lat + "," + lng).apply();
} catch (Exception e) {
    e.printStackTrace();
}
```

---

## 2. Comunicación Segura de Red (Data in Transit)

### Prompt Utilizado para Consulta y Orientación
> *"¿Cómo puedo configurar una aplicación Android para prohibir todo el tráfico HTTP sin cifrar y forzar el uso exclusivo de conexiones seguras HTTPS usando Network Security Configuration en XML?"*

### Investigación Teórica
Por defecto, las aplicaciones pueden ser vulnerables a ataques de intercepción de tráfico de red como Man-In-The-Middle (MITM) si permiten comunicación en texto plano (`http://`). Cuando una app transmite coordenadas o peticiones a servidores de mapas a través de HTTP, cualquier atacante en la misma red Wi-Fi puede espiar o alterar los paquetes de datos.

Mediante el archivo `network_security_config.xml` asignado en el `AndroidManifest.xml`, se declara una política global en el sistema operativo que bloquea a nivel de socket cualquier intento de conexión no cifrada.

### ¿Cómo mejora la seguridad de la aplicación?
Protege la seguridad en tránsito (Data in Transit). Asegura que la aplicación únicamente se comunique mediante protocolos cifrados con TLS/SSL (HTTPS), previniendo la fuga de credenciales, la suplantación de identidad de servidores y la inyección de tráfico malicioso en la red.

### Implementación Técnica en Configuración (XML)

**Creación de `res/xml/network_security_config.xml`:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Prohíbe el tráfico HTTP en texto claro a nivel global -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

**Vinculación en `AndroidManifest.xml`:**
```xml
<application
    android:allowBackup="true"
    android:networkSecurityConfig="@xml/network_security_config"
    ... >
</application>
```

---

## 3. Validación y Sanitización de Entradas (Input Sanitization)

### Prompt Utilizado para Consulta y Orientación
> *"¿Por qué es importante sanitizar las cadenas de texto ingresadas por el usuario en una app Android antes de procesarlas o guardarlas? Muestra un método helper en Java que aplique expresiones regulares (Regex) para limpiar inputs."*

### Investigación Teórica
La entrada no controlada de datos por parte de los usuarios representa una de las vulnerabilidades más comunes en aplicaciones software. Permitir caracteres especiales no filtrados o textos con longitudes desmedidas en campos como notas o nombres de marcadores en el mapa puede provocar fallos de estabilidad (*crashes*), comportamientos anómalos o vulnerabilidades de inyección de código.

La sanitización consiste en aplicar expresiones regulares (Regex) para filtrar activamente cualquier carácter que se salga de los patrones permitidos (whitelist) y limitar el tamaño del buffer recibido.

### ¿Cómo mejora la seguridad de la aplicación?
Aumenta la robustez y resistencia del software. Al limpiar y limitar las entradas antes de procesarlas, se previene la ejecución no deseada de scripts, se evitan desbordamientos de memoria (*buffer overflow*) y se protege la integridad de la base de datos o de los archivos JSON internos.

### Implementación Técnica en Código (Java)

**Antes (Práctica Insegura - Sin Validación):**
```java
// Se procesa el texto tal cual lo ingresa el usuario
String placeName = inputEditText.getText().toString();
savePlace(placeName);
```

**Después (Práctica Segura - Sanitización con Regex):**
```java
// Método de limpieza e inspección de texto
private String sanitizeInput(String input) {
    if (input == null) return "";
    
    String trimmed = input.trim();
    if (trimmed.length() > 50) {
        trimmed = trimmed.substring(0, 50); // Restringe la longitud máxima
    }
    
    // Elimina caracteres especiales no permitidos mediante whitelist Regex
    return trimmed.replaceAll("[^a-zA-Z0-9 áéíóúÁÉÍÓÚñÑ.-]", "");
}
```