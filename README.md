# Chat privado (2 personas)

Portal de chat interno para dos usuarios: mensajes en tiempo real, historial, envío de archivos e imágenes (hasta 25 MB), indicador de "escribiendo…" y estado en línea.

## Requisitos
- Node.js 18 o superior

## Puesta en marcha
```bash
npm install
node setup-users.js usuario1 clave1_larga usuario2 clave2_larga   # mínimo 8 caracteres
npm start
```
Abre `http://localhost:3000` (o `http://IP-DE-TU-MAQUINA:3000` desde otro equipo de la red).
Cambia el puerto con `PORT=8080 npm start`.

## Datos
Todo se guarda en la carpeta `data/`:
- `users.json`: usuarios con contraseñas hasheadas (scrypt)
- `messages.json`: historial
- `uploads/`: archivos adjuntos

Haz copia de seguridad de esa carpeta y no la expongas.

## Seguridad
- Solo los dos usuarios creados pueden entrar; sin sesión no se acceden ni al chat ni a los archivos.
- Límite de intentos de login por IP.
- Para usarlo fuera de tu red local, ponlo detrás de HTTPS (por ejemplo con Caddy o Nginx como proxy inverso); sin HTTPS, las contraseñas y mensajes viajan sin cifrar.
- Las sesiones viven en memoria: al reiniciar el servidor hay que volver a iniciar sesión.
