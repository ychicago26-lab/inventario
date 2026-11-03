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

### Cada salón tiene su propia portada

Además del panel interno, cada salón tiene su propia página pública en
`/p/su-slug`. Se configura entera desde **Ajustes → Portada pública**:
título, texto de bienvenida, descripción, experiencia, cursos, teléfono,
WhatsApp, correo, ciudad, dirección, Instagram, horario y nota del pie.
Desde ahí también se decide si se muestran la galería, el formulario de
reserva y el asistente de chat, y se copia el enlace para compartirlo.

La lista de servicios que aparece en la portada y en el formulario de
reserva es la misma que el salón ya tiene en **Ajustes → Servicios
ofrecidos**, así que no hay que escribirla dos veces.

La portada de KY Nature Beauty sigue en `/`, tal como estaba.

### Tu consola: invitaciones y suspensión

Define `ADMIN_PASSWORD` en Render y tendrás una consola propia en `/admin`.
Nada en la aplicación enlaza a esa dirección. Sin esa variable la consola no
existe y todo funciona como antes.

Desde ahí se hacen dos cosas.

**Invitaciones de un solo uso.** Creas un código para cada salón, con el
nombre de a quién se lo das y una nota tuya. En cuanto alguien abre su salón
con ese código, queda gastado: reenviarlo no sirve de nada. La consola te
muestra cuáles están sin usar, cuáles se gastaron y qué salón salió de cada
una. Una invitación sin usar se puede anular, y se le puede poner fecha de
caducidad.

El consumo es una sola instrucción condicional en la base de datos, así que
si dos personas usan el mismo código a la vez, entra exactamente una.

**Suspensión.** Apaga un salón sin tocar sus datos. Deja de poder entrar, las
sesiones ya abiertas dejan de servir, nadie puede crear cuentas nuevas y su
página pública desaparece. Al reactivarlo vuelve todo tal cual estaba.

El interruptor se guarda fuera de la configuración del salón, en un espacio
al que el salón no tiene ninguna ruta, de modo que un salón suspendido no
puede reactivarse a sí mismo. Los nombres `admin`, `cron` y cualquiera que
empiece por dos guiones bajos están reservados y no se pueden usar como
salón.

Una vez que uses invitaciones, quita `SIGNUP_CODE` del entorno. Un código
compartido se puede pasar de mano en mano, que es justo lo que las
invitaciones existen para evitar. Mientras esté definido sigue funcionando
como alternativa, para que la transición no rompa nada.

### Copia de seguridad

La consola descarga toda la base de datos en un archivo JSON y la vuelve a
cargar desde él. Son dos botones en `/admin`.

Sirve para dos cosas. Para no perder nada, que en un plan gratuito de base
de datos es imprescindible porque no hay copias automáticas. Y para mudarse
de proveedor sin depender de nadie: se descarga la copia, se apunta
`DATABASE_URL` a la base nueva, y se restaura allí.

Restaurar escribe cada registro por su propia clave, así que hacerlo dos
veces no duplica nada y se puede apuntar tanto a una base vacía como a una
que ya tenga parte de esos datos.

### Aislamiento entre salones

Cada salón solo ve lo suyo. Todo se guarda con el identificador del salón,
cada petición exige una sesión firmada que está atada a ese salón concreto,
y una sesión de un salón recibe `401` en cualquier ruta de otro. No existe
ninguna pantalla ni ningún endpoint que liste los salones. Un salón recién
abierto empieza con el inventario, las clientas, la agenda y los reportes
completamente vacíos.

El endpoint público de la portada solo devuelve los campos que el propio
salón decidió publicar, nunca la configuración entera, así que añadir un
campo privado a la configuración más adelante no puede filtrarlo por
descuido.

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
  reinicia el proceso (cada redeploy, por ejemplo). El Blueprint ya lo
  genera solo.
- `SIGNUP_CODE` — el código que hay que escribir para abrir un salón nuevo.
  Se compara sin distinguir mayúsculas de minúsculas y sin tener en cuenta
  los espacios ni los guiones, porque los teclados de móvil no siempre ponen
  mayúsculas y al pegar suele colarse un espacio. El código de invitación de
  cada salón se compara igual. Ambas comparaciones son de tiempo constante.
  Mientras esté definido, la pantalla de bienvenida pide ese código y sin él
  no se puede crear ningún salón. Si se deja vacío, cualquiera que conozca
  la dirección puede abrir el suyo. No afecta a los salones ya existentes ni
  al inicio de sesión del personal, que sigue usando el código de invitación
  propio de cada salón.

El chat usa **Anthropic** siempre que `ANTHROPIC_API_KEY` esté definida, y
solo recurre a Gemini cuando no lo está. Si están las dos, manda Anthropic.

### Correos por Gmail

Con estas variables la aplicación envía tres correos. Sin ellas funciona
exactamente igual, solo que no envía nada.

- `GMAIL_USER` — la dirección de Gmail desde la que salen los correos.
- `GMAIL_APP_PASSWORD` — una **contraseña de aplicación** de esa cuenta de
  Google, no la contraseña normal. Se genera en la cuenta de Google, en
  Seguridad → Verificación en dos pasos → Contraseñas de aplicaciones. Hay
  que tener la verificación en dos pasos activada para que aparezca.
- `MAIL_FROM_NAME` — el nombre que verá quien reciba el correo. Opcional.

Los tres correos son:

1. **Bienvenida**, al abrir un salón nuevo, con sus dos enlaces y los
   primeros pasos. Va al correo que el salón escribe al registrarse.
2. **Confirmación de cita**, cuando el salón confirma una solicitud. Va a la
   clienta, si dejó su correo. Al mismo tiempo, el salón recibe un aviso de
   cada solicitud nueva.
3. **Recordatorio**, el día antes de la cita.

Gmail permite unos 500 correos al día desde una cuenta normal, de sobra para
un salón. Si algún día hace falta más, o se quiere enviar desde un dominio
propio, conviene pasar a un servicio de correo transaccional.

Si un correo falla, no se pierde nada: la reserva, la cita y la cuenta se
guardan igual, y el fallo solo queda en los registros del servidor.

### Recordatorios diarios

El envío de recordatorios es un endpoint, no un temporizador interno, porque
en el plan gratuito de Render el servicio se duerme a los 15 minutos y un
temporizador simplemente no se ejecutaría.

```
POST /api/cron/reminders
x-cron-secret: <el valor de CRON_SECRET>
```

Busca las citas del día siguiente que tengan correo y no hayan sido avisadas
todavía, envía el recordatorio y las marca. Ejecutarlo dos veces el mismo día
no envía nada por duplicado, y una cita cuyo correo falló queda sin marcar
para reintentarla en la siguiente ejecución.

Para dispararlo una vez al día hay dos caminos. Un **Cron Job de Render**,
que es lo más limpio pero requiere plan de pago. O un servicio gratuito de
cron externo, como cron-job.org, configurado para hacer ese POST con la
cabecera. Sin `CRON_SECRET` definida, el endpoint responde `503` y no hace
nada.

### Añadir una cita al calendario

En la Agenda, cada cita tiene un botón que descarga un archivo `.ics`
estándar. Se abre en Apple Calendar, Google Calendar y Outlook, y ya trae dos
avisos puestos: uno el día antes y otro dos horas antes. No hace falta
ninguna cuenta, ningún permiso ni ningún servicio externo.

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
