# KY Nature Beauty — Inventario

Aplicación web de inventario, ventas y agenda para salones de belleza.

## ⚠️ Importante sobre esta copia

Este repositorio contiene el mismo código que la versión publicada en Claude
(Artifacts). Al desplegarla aquí como sitio estático (GitHub Pages / Render
Static Site), **dos funciones dejan de estar disponibles**, porque dependen
del entorno de ejecución de Claude (`window.claude`), que solo existe dentro
del visor de Artifacts de claude.ai:

- **Sincronización de datos entre dispositivos.** Sin ese entorno, la app
  usa `localStorage` como respaldo: cada navegador/dispositivo guarda su
  propio inventario, ventas y agenda de forma aislada, sin compartirse.
- **Asistente de chat con IA (RAG).** El botón de chat simplemente no
  aparece, porque depende de la capacidad `sample` de Claude.

Para tener la app 100% funcional (datos compartidos entre celular, tablet y
computadora, más el asistente de IA), usa el enlace publicado en Claude:
https://claude.ai/artifact/1GLwAEdT3gVPxo7gEHfcmb

Esta copia es útil si quieres una versión ligera, de un solo dispositivo,
en tu propio dominio.

## Desplegar en Render

1. Entra a [render.com](https://render.com) → **New +** → **Static Site**.
2. Conecta este repositorio (`inventario`).
3. Build command: (vacío). Publish directory: `.`
4. Deploy. Render te dará una URL pública lista para usar.

No se necesita ninguna clave de API para este tipo de despliegue.
