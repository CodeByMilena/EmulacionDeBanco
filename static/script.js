let timer;

    // Función para cerrar sesión
    function cerrarSesion() {
        window.location.href = '/logout'; // Cambia '/logout' a la ruta que maneja el cierre de sesión
    }

    // Función para mostrar el diálogo de cierre de sesión
    function mostrarDialogoCierre() {
        // Crear un div para el diálogo
        const dialogo = document.createElement('div');
        dialogo.style.position = 'fixed';
        dialogo.style.top = '50%';
        dialogo.style.left = '50%';
        dialogo.style.transform = 'translate(-50%, -50%)';
        dialogo.style.backgroundColor = '#fff';
        dialogo.style.padding = '20px';
        dialogo.style.boxShadow = '0 0 10px rgba(0,0,0,0.5)';
        dialogo.style.zIndex = '1000';

        // Texto del diálogo
        const mensaje = document.createElement('p');
        mensaje.textContent = "Tu sesión ha estado inactiva por 30 segundos. Se cerrará automáticamente.";
        dialogo.appendChild(mensaje);

        // Botón de aceptar
        const botonAceptar = document.createElement('button');
        botonAceptar.textContent = 'Aceptar';
        botonAceptar.onclick = function() {
            cerrarSesion();
        };
        dialogo.appendChild(botonAceptar);

        // Agregar el diálogo al body
        document.body.appendChild(dialogo);
    }

    // Función para iniciar el temporizador
    function iniciarTemporizador() {
        clearTimeout(timer);

        // Iniciar un nuevo temporizador
        timer = setTimeout(function() {
            mostrarDialogoCierre(); // Mostrar el diálogo en lugar de confirm
        }, 30000); // 30000 ms = 30 segundos
    }

    // Iniciar el temporizador al cargar la página
    iniciarTemporizador();

    // Reiniciar el temporizador en cualquier interacción
    document.addEventListener('click', iniciarTemporizador);
    document.addEventListener('keypress', iniciarTemporizador);
    document.addEventListener('mousemove', iniciarTemporizador);
    document.addEventListener('touchstart', iniciarTemporizador); // Para dispositivos táctiles
