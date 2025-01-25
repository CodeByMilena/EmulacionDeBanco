from flask import Flask, render_template, request, redirect, flash, session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Email, ValidationError
import pymysql
import bcrypt
import re
import random
from cryptography.fernet import Fernet
import base64
import os

app = Flask(__name__)
app.secret_key = 'mysecretkey'  # Necesario para manejar sesiones

# Formulario para cerrar sesión
class LogoutForm(FlaskForm):
    pass  # No se necesitan campos


# Validar contraseña
def validate_password(form, field):
    password = field.data
    if not (10 <= len(password) <= 15):
        raise ValidationError('La contraseña debe tener entre 10 y 15 caracteres.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('La contraseña debe contener al menos una letra mayúscula.')
    if not re.search(r'\d', password):
        raise ValidationError('La contraseña debe contener al menos un número.')
    if not re.search(r'[@$!%*?&]', password):
        raise ValidationError('La contraseña debe contener al menos un carácter especial.')

# Generar CBU y número de cuenta
def generate_account_details():
    cbu = ''.join([str(random.randint(0, 9)) for _ in range(22)])  # Genera un CBU de 22 dígitos
    return cbu

def generate_key():
    return base64.urlsafe_b64encode(os.urandom(32))

# Utiliza esta clave para crear una instancia de Fernet.
key = generate_key()  # En producción, carga esto desde un lugar seguro
cipher = Fernet(key)

def encrypt_amount(amount):
    # Convierte el monto a bytes y encripta
    return cipher.encrypt(str(amount).encode())

def decrypt_amount(encrypted_amount):
    # Desencripta y convierte de nuevo a decimal
    return Decimal(cipher.decrypt(encrypted_amount).decode())

# Crear formulario de registro
class RegistrationForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    contraseña = PasswordField('Contraseña', validators=[DataRequired(), validate_password])

# Configuración de MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  # Usuario predeterminado en XAMPP
app.config['MYSQL_PASSWORD'] = ''  # La contraseña de root en XAMPP suele estar vacía por defecto
app.config['MYSQL_DB'] = 'banco'

# Conectar a la base de datos
def get_db_connection():
    connection = pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB'],
        cursorclass=pymysql.cursors.DictCursor
    )
    return connection

# Página principal de inicio de sesión
@app.route('/')
def index():
    return render_template('login.html')

def generate_cbu():
    return ''.join([str(random.randint(0, 9)) for _ in range(10)])

# Página de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        nombre = form.nombre.data
        email = form.email.data
        contraseña = form.contraseña.data
        
        # Encriptar la contraseña
        hashed_password = bcrypt.hashpw(contraseña.encode('utf-8'), bcrypt.gensalt())
        
        # Generar CBU (10 dígitos aleatorios)
        cbu = generate_cbu()

        # Definir alias fijo
        alias = 'e.tecnica.32'

        # Saldo inicial
        saldo_inicial = 0.00

        # Insertar los datos en la base de datos
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                # Insertar usuario en la tabla usuarios
                cursor.execute('INSERT INTO usuarios (nombre, email, contraseña) VALUES (%s, %s, %s)', 
                               (nombre, email, hashed_password))
                # Obtener el ID del usuario recién creado
                user_id = cursor.lastrowid

                # Insertar la cuenta bancaria en la tabla ctaBancaria
                cursor.execute('INSERT INTO ctaBancaria (usuario_id, cbu, alias, saldos) VALUES (%s, %s, %s, %s)', 
                               (user_id, cbu, alias, saldo_inicial))
            
            # Confirmar los cambios
            connection.commit()
        finally:
            # Cerrar la conexión
            connection.close()
        
        # Mostrar mensaje de éxito y redirigir
        flash('Cuenta creada exitosamente. ¡Ahora puedes iniciar sesión!', 'success')
        return redirect('/')
    
    return render_template('register.html', form=form)

# Verificación del inicio de sesión
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    contraseña = request.form['contraseña']
    
    # Consultar el usuario por su email
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM usuarios WHERE email = %s', (email,))
            usuario = cursor.fetchone()
    finally:
        connection.close()
    
    # Si se encuentra el usuario, verificar la contraseña
    if usuario and bcrypt.checkpw(contraseña.encode('utf-8'), usuario['contraseña'].encode('utf-8')):
        # Establecer la sesión
        session['loggedin'] = True
        session['id'] = usuario['id']
        session['nombre'] = usuario['nombre']
        
        # Agregar la línea para asegurar el alias:
        session['alias'] = usuario.get('alias', 'Alias no disponible')  # Asegúrate de que el alias exista

        flash(f'¡Bienvenido {usuario["nombre"]}!', 'success')
        return redirect('/dashboard')  # Redirigir a una página de inicio para usuarios logueados
    else:
        flash('Correo o contraseña incorrectos', 'danger')
        return redirect('/')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'loggedin' in session:
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                if request.method == 'POST':
                    # Obtener el monto ingresado y convertirlo a float
                    monto = float(request.form['monto'])
                    
                    # Validar que el monto sea positivo
                    if monto <= 0:
                        flash('El monto debe ser positivo.', 'danger')
                    else:
                        # Actualizar el saldo en la base de datos
                        cursor.execute('UPDATE ctaBancaria SET saldos = saldos + %s WHERE usuario_id = %s', (monto, session['id']))
                        connection.commit()
                        flash('Saldo actualizado exitosamente.', 'success')

                # Obtener detalles de la cuenta
                cursor.execute('SELECT cbu, saldos, alias FROM ctaBancaria WHERE usuario_id = %s', (session['id'],))
                cuenta = cursor.fetchone()
                if cuenta:
                    session['cbu'] = cuenta['cbu']
                    session['saldos'] = cuenta['saldos']
                    session['alias'] = cuenta['alias']  # Recuperar el alias correctamente

                # Obtener transacciones recientes
                cursor.execute("""
                SELECT 
                    t.monto, 
                    t.fecha, 
                    u1.nombre AS nombre_origen, 
                    u2.nombre AS nombre_destinatario, 
                    t.tipo
                FROM 
                    transacciones t 
                JOIN 
                    usuarios u1 ON t.origen = u1.id 
                JOIN 
                    usuarios u2 ON t.destinatario = u2.id 
                WHERE 
                    t.origen = %s OR t.destinatario = %s 
                ORDER BY 
                    t.fecha DESC
                """, (session['id'], session['id']))
                transacciones = cursor.fetchall()

        finally:
            connection.close()
        
        logout_form = LogoutForm()  # Crear una instancia del formulario de cierre de sesión
        return render_template('home.html', form=logout_form, transacciones=transacciones, saldos=session['saldos'], alias=session['alias'])
    else:
        flash('Por favor, inicia sesión primero', 'warning')
        return redirect('/')


@app.route('/editar_alias', methods=['GET', 'POST'])
def editar_alias():
    if request.method == 'POST':
        # Cambiamos 'alias' a 'nuevo_alias' para coincidir con el formulario
        nuevo_alias = request.form.get('nuevo_alias')
        if not nuevo_alias:
            flash('El campo nuevo alias es obligatorio', 'danger')
            return redirect(url_for('editar_alias'))

        # Actualiza el alias en la base de datos
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute('UPDATE ctaBancaria SET alias = %s WHERE usuario_id = %s', (nuevo_alias, session['id']))
                connection.commit()
                flash('Alias actualizado correctamente.', 'success')
        finally:
            connection.close()

        return redirect(url_for('dashboard'))

    # En la solicitud GET, mostrar el formulario de edición
    return render_template('editar_alias.html', alias=session.get('alias'))

@app.route('/transferencia', methods=['POST'])
def transferencia():
    if 'id' not in session:
        flash('Por favor, inicia sesión primero', 'error')
        return redirect(url_for('login'))

    usuario_id = session['id']
    cbu_alias = request.form['cbu_alias']  # Ahora puede ser CBU o alias
    monto = Decimal(request.form['monto'])  # Cambia a Decimal

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Verificar saldo del usuario
            cursor.execute("SELECT saldos FROM ctaBancaria WHERE usuario_id = %s", (usuario_id,))
            cuenta_origen = cursor.fetchone()

            if cuenta_origen is None:
                flash('Cuenta de origen no encontrada', 'error')
                return redirect(url_for('dashboard'))

            if cuenta_origen['saldos'] < monto:
                flash('Saldo insuficiente', 'danger')
                return redirect(url_for('dashboard'))

            # Buscar al destinatario por CBU o Alias
            cursor.execute("SELECT usuario_id, nombre FROM ctaBancaria JOIN usuarios ON ctaBancaria.usuario_id = usuarios.id WHERE cbu = %s OR alias = %s", (cbu_alias, cbu_alias))
            cuenta_destinatario = cursor.fetchone()

            if cuenta_destinatario is None:
                flash('El CBU o Alias del destinatario no existe', 'danger')
                return redirect(url_for('dashboard'))

            destinatario_id = cuenta_destinatario['usuario_id']
            destinatario_nombre = cuenta_destinatario['nombre']

            # Realizar la transferencia
            nuevo_saldo_origen = cuenta_origen['saldos'] - monto
            cursor.execute("UPDATE ctaBancaria SET saldos = %s WHERE usuario_id = %s", (nuevo_saldo_origen, usuario_id))

            cursor.execute("SELECT saldos FROM ctaBancaria WHERE usuario_id = %s", (destinatario_id,))
            cuenta_destino = cursor.fetchone()
            nuevo_saldo_destino = cuenta_destino['saldos'] + monto
            cursor.execute("UPDATE ctaBancaria SET saldos = %s WHERE usuario_id = %s", (nuevo_saldo_destino, destinatario_id))

            # Registrar la transacción
            cursor.execute(
                "INSERT INTO transacciones (origen, destinatario, monto, tipo) VALUES (%s, %s, %s, 'pago')",
                (usuario_id, destinatario_id, monto)
            )
            connection.commit()

        flash('Transferencia realizada con éxito', 'success')
    finally:
        connection.close()

    return redirect(url_for('dashboard'))



from flask import session, redirect, url_for, flash

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """Cierra la sesión del usuario y redirige a la página de inicio."""
    # Eliminar toda la información de la sesión
    session.clear()
    
    # Flash message opcional para notificar el cierre de sesión
    flash('Has cerrado sesión exitosamente.', 'success')
    
    # Redirigir a la página de inicio o de inicio de sesión
    return render_template('login.html')


from decimal import Decimal


# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(debug=True)
