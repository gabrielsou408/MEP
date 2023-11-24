import mysql.connector


def create_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="usuario",
            password="senha",
            database="mkterp_pro"
        )
        if connection.is_connected():
            return connection
    except Exception as e:
        print(f"Erro durante a conexão: {e}")
        return None
