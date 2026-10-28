# KY Nature Beauty — Inventario

Aplicación web de inventario, ventas, fórmulas de coloración y agenda para
salones de belleza, con asistente de IA. Incluye dos formas de usarla:

## 1. Versión en Claude (ya funciona, sin configurar nada)

https://claude.ai/artifact/1GLwAEdT3gVPxo7gEHfcmb

Base de datos compartida y asistente de IA incluidos de fábrica.

## 2. Versión con backend propio (este repo, para desplegar en Render)

Esta carpeta ahora es una aplicación Node.js completa:

- `server.js` — backend Express con PostgreSQL (guarda inventario, ventas,
  clientas, agenda y las cuentas de usuario) y un endpoint de chat que llama
  a la API de Gemini (o a Anthropic como respaldo si esa es la que está
  configurada).
- `public/index.html` — el frontend, adaptado para hablar con ese backend
  en vez de usar las capacidades propias de Claude Artifacts.
- `render.yaml` — Blueprint que crea automáticamente el servicio web **y**
  la base de datos PostgreSQL juntos, ya conectados.

### Cuentas de usuario

Cada salón ya no tiene una sola contraseña compartida: cada persona que
trabaja ahí crea su propia cuenta (nombre completo + contraseña propia),
con recuperación de contraseña mediante una pregunta de seguridad personal.
Desde Ajustes → Equipo se pueden agregar o quitar cuentas (no se puede
eliminar la última cuenta activa de un salón).

### Variables de entorno

En la pestaña Environment del servicio, además de `DATABASE_URL` (la crea
sola el Blueprint), conviene agregar:

- `GEMINI_API_KEY` — para el asistente de chat con inteligencia artificial
  (se obtiene gratis en aistudio.google.com/apikey). Sin esta variable (ni
  `ANTHROPIC_API_KEY`), el chat sigue funcionando con un conjunto de
  respuestas locales basadas en los datos reales del salón, solo que sin
  inteligencia artificial.
- `SESSION_SECRET` — un valor propio, largo y aleatorio, para firmar las
  sesiones de inicio de sesión. Si no se define, el servidor genera uno al
  arrancar, pero entonces todas las sesiones se cierran cada vez que Render
  reinicia el proceso (cada redeploy, por ejemplo).

### Desplegar (reemplaza el Static Site anterior)

Un **Static Site** de Render no puede ejecutar este backend (necesita un
proceso Node corriendo). Para desplegar esta versión:

1. En el dashboard de Render, borra el Static Site anterior (o déjalo, no
   hace daño, pero ya no se actualizará con los pushes de este repo).
2. **New +** → **Blueprint** → selecciona el repositorio `inventario`.
   Render leerá `render.yaml` y creará solo:
   - La base de datos PostgreSQL (`inventario-db`).
   - El servicio web (`inventario`), ya conectado a esa base de datos.
3. Antes de confirmar el despliegue, Render te pedirá el valor de
   **`GEMINI_API_KEY`** y **`ANTHROPIC_API_KEY`** (porque el Blueprint las
   marca como secretas y no las trae solas). Puedes dejar ambas en blanco y
   agregarlas después desde Environment, o pegar ahí tu propia clave de
   Gemini (aistudio.google.com/apikey, gratis) o de Anthropic
   (console.anthropic.com). Sin ninguna de las dos, el chat sigue
   funcionando con respuestas locales, solo que sin inteligencia artificial.
4. Deploy. En 2-3 minutos tendrás una URL como
   `https://inventario-xxxx.onrender.com`.

Cada salón que visite esa URL por primera vez (`/`) verá la pantalla de
bienvenida y, al terminarla, obtendrá su propio enlace
(`/s/su-salon-xxxx`) con sus propios datos, aislados de los demás.

### Nota sobre el plan gratuito

El plan **free** de Render borra la base de datos PostgreSQL a los 30 días
y "duerme" el servicio web tras 15 minutos sin uso (la primera visita tras
dormir tarda unos segundos en responder). Para un salón en producción,
conviene pasar al plan pago cuando estés listo.
