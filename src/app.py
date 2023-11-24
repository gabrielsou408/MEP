
import os
from smtplib import SMTPException

from dotenv import load_dotenv
from flask import (Flask, flash, redirect, render_template, request, session,
                   url_for)
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo

from db_connector import create_connection

load_dotenv()


app = Flask(__name__)

csrf = CSRFProtect(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'mkterp.pro@gmail.com'
app.config['MAIL_PASSWORD'] = 'sjsssiqbwiinksev'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

connection = create_connection()


class RegistrationForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    confirm_senha = PasswordField('Confirmar Senha', validators=[
                                  DataRequired(), EqualTo('senha')])
    contato = StringField('Contato')
    submit = SubmitField('Registrar')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route('/register', methods=['POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(
            form.senha.data, method='scrypt')
        cursor = connection.cursor()
        tel = "+55"+form.contato.data[1:3] + \
            form.contato.data[4:8]+form.contato.data[9:]
        cursor.execute("INSERT INTO Usuarios (nome, email, senha, contato) VALUES (%s, %s, %s, %s)",
                       (form.nome.data, form.email.data, hashed_password, tel))
        connection.commit()
        flash('Conta criada com sucesso!', 'success')
        return redirect(url_for('index'))
    flash('Erro ao criar conta. Verifique os dados e tente novamente.', 'danger')
    return redirect(url_for('index'))


@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            # Estabelece uma nova conexão
            connection = create_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                "SELECT * FROM Usuarios WHERE email=%s", (form.email.data,))
            user = cursor.fetchone()

            if not user or not check_password_hash(user['senha'], form.senha.data):
                flash('Email ou senha incorretos!', 'danger')
                return redirect(url_for('index'))

            session['username'] = user['nome']
            session['permissao'] = user['permissao']

            # Verificar se o usuário é um funcionário e buscar o departamento_id
            cursor.execute(
                "SELECT departamento_id FROM Funcionarios WHERE usuario_id = %s", (user['usuario_id'],))
            funcionario_data = cursor.fetchone()
            if funcionario_data:
                session['departamento_id'] = funcionario_data['departamento_id']
            else:
                session['departamento_id'] = None  # Caso não seja funcionário
        finally:
            # Fecha a conexão com o banco de dados
            if connection.is_connected():
                cursor.close()
                connection.close()

        return redirect(url_for('dashboard'))
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    username = session.get('username', 'Visitante')
    permissao = session.get('permissao', 'Convidado')
    departamento_id = session.get('departamento_id', None)

    convidados = []
    if permissao in ['Admin', 'Gerente']:
        try:
            # Estabelece uma nova conexão
            connection = create_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                "SELECT usuario_id, nome, permissao FROM Usuarios WHERE permissao='Convidado'")
            convidados = cursor.fetchall()
        finally:
            # Fecha a conexão com o banco de dados
            if connection.is_connected():
                cursor.close()
                connection.close()

    return render_template('dashboard.html', username=username, permissao=permissao, convidados=convidados, departamento_id=departamento_id)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/logout')
def logoff():
    session.clear()
    flash('Você saiu com sucesso!', 'success')
    return redirect(url_for('index'))


@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.form.get('email')

    cursor = connection.cursor()
    cursor.execute("SELECT email FROM Usuarios WHERE email=%s", (email,))
    user = cursor.fetchone()

    if user:
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        token = s.dumps(email, salt='recover-key')

        recover_url = url_for('reset_password', token=token, _external=True)

        msg = Message('Recupere sua senha',
                      sender='mkterp.pro@gmail.com', recipients=[email])
        msg.body = 'Clique no link a seguir para redefinir sua senha: {}'.format(
            recover_url)
        mail.send(msg)

        flash('Email enviado com instruções para redefinir sua senha!', 'info')
    else:
        flash('Email não encontrado!', 'danger')

    return redirect(url_for('index'))


@app.route('/reset_password/<token>', methods=['GET'])
def reset_password(token):
    return render_template('reset_password.html', token=token)


@app.route('/process_reset_password', methods=['POST'])
def process_reset_password():
    token = request.form.get('token')
    print("Entrou na função reset_password")

    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='recover-key', max_age=3600)
        print(f"Email deserializado do token: {email}")
    except (SignatureExpired, BadSignature):
        print("Erro ao deserializar o token ou token expirado")
        flash('O link é inválido ou expirou!', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        print("Método POST detectado")
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password == confirm_password:
            print("Novas senhas coincidem")
            hashed_password = generate_password_hash(
                new_password, method='scrypt')

            cursor = connection.cursor()
            cursor.execute(
                "UPDATE Usuarios SET senha=%s WHERE email=%s", (hashed_password, email))
            connection.commit()

            print("Senha atualizada no banco de dados")
            flash('Senha redefinida com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            print("As senhas fornecidas não coincidem")
            flash('As senhas não coincidem!', 'danger')
            return redirect(url_for('reset_password', token=token))

    print("Renderizando o template reset_password.html")
    return render_template('reset_password.html')


@app.route('/send_email', methods=['POST'])
def send_email():
    nome = request.form.get('Nome')
    telefone = request.form.get('Telefone')
    email = request.form.get('email')
    mensagem = request.form.get('Mensagem')

    message = Message(subject="Novo contato de " + nome,
                      sender=email,
                      recipients=['mkterp.pro@gmail.com'])

    message.body = f"""
    De: {nome} <{email}>
    Telefone: {telefone}
    Mensagem:
    {mensagem}
    """

    try:
        mail.send(message)
        flash('E-mail enviado com sucesso!', 'success')
    except SMTPException:
        flash('Ocorreu um erro ao enviar o e-mail. Tente novamente mais tarde.', 'danger')

    return redirect('/')


@app.route('/manage_users')
def manage_users():
    if not session.get('permissao') in ['Admin', 'Gerente']:
        flash('Acesso negado.', 'danger')
        return '', 403
    # Criar uma nova conexão para cada requisição
    connection = create_connection()

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT usuario_id, nome, permissao FROM Usuarios WHERE permissao = 'Convidado'"
        )
        convidados = cursor.fetchall()
    finally:
        # Fechar a conexão após o uso
        cursor.close()
        connection.close()

    # Retorne apenas a seção relevante da página
    return render_template('user_management_section.html', convidados=convidados)


@app.route('/update_permission/<int:user_id>', methods=['POST'])
def update_permission(user_id):
    if not session.get('permissao') in ['Admin', 'Gerente']:
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))
    nova_permissao = request.form.get('permissao')
    try:
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE Usuarios SET permissao = %s WHERE usuario_id = %s", (
                nova_permissao, user_id)
        )
        connection.commit()
        cursor.execute(
            "SELECT * FROM Usuarios WHERE usuario_id = %s", (user_id,))
        updated_user = cursor.fetchone()
        print(f"Usuário atualizado: {updated_user}")
        flash('Permissão atualizada com sucesso!', 'success')
    except Exception as e:
        print(f"Exceção capturada: {e}")
        connection.rollback()
        flash(f'Erro ao atualizar permissão: {e}', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/listar_funcionarios')
def listar_funcionarios():
    connection = create_connection()

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
        SELECT f.nome, f.email, d.nome AS departamento
        FROM Funcionarios f
        JOIN Departamentos  d ON f.departamento_id = d.departamento_id 
        ORDER BY f.nome ASC
        """)
        funcionarios = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return render_template('lista_funcionarios.html', funcionarios=funcionarios)


@app.route('/adicionar_funcionario')
def adicionar_funcionario():
    # Verifique as permissões do usuário aqui

    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        # Consulta para buscar usuários elegíveis
        cursor.execute(
            """
            SELECT usuario_id, nome, email
            FROM Usuarios
            WHERE permissao = 'Usuario' AND usuario_id NOT IN (SELECT usuario_id FROM Funcionarios)
            ORDER BY nome
            """
        )
        usuarios_elegiveis = cursor.fetchall()

        # Consulta para buscar departamentos
        cursor.execute(
            "SELECT departamento_id, nome FROM Departamentos ORDER BY nome")
        departamentos = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return render_template('adicionar_funcionario.html', usuarios=usuarios_elegiveis, departamentos=departamentos)


@app.route('/processar_adicao_funcionario', methods=['POST'])
def processar_adicao_funcionario():
    # Verifique as permissões do usuário aqui
    nome = request.form.get('nome')
    email = request.form.get('email')
    usuario_id = request.form.get('usuario_id')
    departamento_id = request.form.get('departamento_id')
    cargo = request.form.get('cargo')
    data_contratacao = request.form.get('data_contratacao')
    salario = request.form.get('salario')
    print(nome + " - " + email + " - " + str(usuario_id) + " - " +
          str(departamento_id) + " - " + cargo + " - " + data_contratacao + " - " + salario)
    try:
        connection = create_connection()
        cursor = connection.cursor()

        cursor.execute(
            "INSERT INTO Funcionarios (nome, email, cargo, data_contratacao, salario, departamento_id, usuario_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (nome, email, cargo, data_contratacao,
             salario, departamento_id, usuario_id)
        )

        connection.commit()
        cursor.close()
        connection.close()

        flash('Funcionário adicionado com sucesso!', 'success')
    except Exception as e:
        print(f"Erro ao adicionar funcionário: {e}")
        flash(f'Erro ao adicionar funcionário: {e}', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/gerenciar_projetos')
def gerenciar_projetos():
    try:
        # Estabelece uma nova conexão
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        # Buscar todos os projetos
        cursor.execute("""
            SELECT Projetos.*, Clientes.nome AS nome_cliente
            FROM Projetos
            INNER JOIN Clientes ON Projetos.cliente_id = Clientes.cliente_id
        """)

        projetos = cursor.fetchall()

        # Enviar os dados para o template
        return render_template('gerenciar_projetos.html', projetos=projetos)

    except Exception as e:
        print(f"Erro ao buscar projetos: {e}")

    finally:
        # Fecha a conexão com o banco de dados
        if connection.is_connected():
            cursor.close()
            connection.close()


@app.route('/verificar_cliente')
def verificar_cliente():
    # Verifique as permissões do usuário aqui

    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        # Consulta para buscar todos os clientes
        cursor.execute("SELECT cliente_id, nome FROM Clientes ORDER BY nome")
        clientes = cursor.fetchall()
    finally:
        cursor.close()
        connection.close()

    return render_template('verificar_cliente.html', clientes=clientes)


@app.route('/adicionar_projeto')
def adicionar_projeto():
    cliente_id = request.args.get('cliente_id')
    return render_template('adicionar_projeto.html', cliente_id=cliente_id)


@app.route('/salvar_projeto', methods=['POST'])
def salvar_projeto():
    nome = request.form.get('nome')
    cliente_id = request.form.get('cliente_id')
    data_inicio = request.form.get('data_inicio')
    data_fim = request.form.get('data_fim')
    status = request.form.get('status')
    valor_contrato = request.form.get('valor_contrato')
    dias_de_execucao = request.form.get('dias_de_execucao')

    # Código para inserir os dados no banco de dados
    try:
        connection = create_connection()
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO Projetos (nome, cliente_id, data_inicio, data_fim, status, valor_contrato, dias_de_execucao)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (nome, cliente_id, data_inicio, data_fim, status, valor_contrato, dias_de_execucao))
        connection.commit()
        flash('Projeto adicionado com sucesso!', 'success')
    except Exception as e:
        print(f"Erro ao adicionar projeto: {e}")
        flash(f'Erro ao adicionar projeto: {e}', 'danger')
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('dashboard'))


@app.route('/confirmar_exclusao/<int:projeto_id>')
def confirmar_exclusao(projeto_id):
    return render_template('confirmar_exclusao.html', projeto_id=projeto_id)


@app.route('/excluir_projeto/<int:projeto_id>', methods=['POST'])
def excluir_projeto(projeto_id):
    try:
        connection = create_connection()
        cursor = connection.cursor()
        cursor.execute(
            "DELETE FROM Projetos WHERE projeto_id = %s", (projeto_id,))
        connection.commit()
        flash('Projeto excluído com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao excluir projeto: {e}', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/editar_projeto/<int:projeto_id>')
def editar_projeto(projeto_id):
    try:
        # Estabelecer conexão com o banco de dados
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        # Buscar dados do projeto e o nome do cliente em uma única consulta
        cursor.execute("""
            SELECT Projetos.*, Clientes.nome AS cliente_nome
            FROM Projetos
            JOIN Clientes ON Projetos.cliente_id = Clientes.cliente_id
            WHERE Projetos.projeto_id = %s
        """, (projeto_id,))

        projeto = cursor.fetchone()

        if not projeto:
            flash('Projeto não encontrado.', 'warning')
            return redirect(url_for('dashboard'))

    except Exception as e:
        flash(f'Erro ao buscar informações do projeto: {e}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        cursor.close()
        connection.close()

    return render_template('editar_projeto.html', projeto=projeto)


@app.route('/atualizar_projeto', methods=['POST'])
def atualizar_projeto():
    projeto_id = request.form.get('projeto_id')
    nome = request.form.get('nome')
    data_inicio = request.form.get('data_inicio')
    data_fim = request.form.get('data_fim')
    status = request.form.get('status')
    valor_contrato = request.form.get('valor_contrato')
    dias_de_execucao = request.form.get('dias_de_execucao')

    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            UPDATE Projetos SET nome=%s, data_inicio=%s, data_fim=%s, status=%s, valor_contrato=%s, dias_de_execucao=%s
            WHERE projeto_id=%s
        """, (nome, data_inicio, data_fim, status, valor_contrato, dias_de_execucao, projeto_id))
        connection.commit()
        flash('Projeto editado com sucesso!', 'success')
    except Exception as e:
        print(f"Erro ao atualizar projeto: {e}")
        flash(f'Erro ao editar projeto: {e}', 'danger')
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
