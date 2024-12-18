# client/client_main.py
import sys
import socket
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QMessageBox)
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTextEdit, QPushButton, QLabel)
from PyQt5.QtGui import QColor, QTextCharFormat, QBrush
from PyQt5.QtWidgets import QFileDialog
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from RC4 import RC4
from miscellaneous import generate_odd_64bit, hash_md5, mod_exp, validate_credentials
from logger import Logger

logger = Logger()

class MessageThread(QThread):
    message_received = pyqtSignal(str, str) # Сигнал для передачи сообщений (зашифрованное, расшифрованное)
    keys_received = pyqtSignal(int, int)  # Сигнал для передачи открытого ключа RSA (e, n)
    
    def __init__(self, client, chat_window):
        super().__init__()
        self.client = client
        self.chat_window = chat_window
        self._running = True
        # Сигнал получения ключей к обработчику в окне чата
        self.keys_received.connect(self.chat_window.handle_keys_received)
        
    def stop(self):
        self._running = False
        
    def run(self):
        """Основной метод потока - чтение и обработка входящих сообщений"""
        try:
            buffer = ""  # Буфер для накопления входящих данных
            while self._running:
                try:
                    # Читаем данные из сокета порциями по 4096 байт
                    part = self.client.socket.recv(4096).decode()
                    if not part:  # Если это не часть сообщения, не прикрепляем блок
                        break
                    buffer += part
                    
                    # Если получено полное сообщение (заканчивается на \n)
                    if buffer.endswith("\n"):
                        message = buffer.strip()
                        # Если окно чата существует и инициализирован RC4
                        if self.chat_window and self.chat_window.rc4:
                            # Расшифровываем сообщение
                            decrypted = self.chat_window.rc4.encrypt(message)
                            # Если это сообщение с ключами RSA
                            if decrypted.startswith("KEYS|"):
                                _, e, n = decrypted.split("|")
                                # Отправляем сигнал с полученными ключами
                                self.keys_received.emit(int(e), int(n))
                                logger.info("Получен открытый ключ ClientO: e=%s, n=%s" % (e, n))
                            else:
                                # Иначе это обычное сообщение - отправляем сигнал
                                self.message_received.emit(message, decrypted)
                        buffer = ""  # Очищаем буфер
                        
                except socket.timeout:
                    continue  # При таймауте продолжаем работу
                    
        except Exception as e:
            logger.error(f"Ошибка в потоке сообщений: {e}")

class Client:
    """Клиентская часть приложения."""
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.login = ""
        self.password = ""
        # Поля для криптографии
        self.A = None
        self.g = None
        self.p = None
        self.b = None
        self.B = None
        self.K = None

        self.server_e = None  # Открытый ключ сервера
        self.server_n = None  # Открытый ключ сервера

        # Поля для чата
        self.chat_window = None
        # Поток для приема сообщений
        self.message_thread = None 
        
    def handle_message(self, encrypted: str, decrypted: str):
        if self.chat_window:
            self.chat_window.message_received.emit(encrypted, decrypted)

    def connect(self):
        if not self.socket:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))

    def register(self, login: str, password: str) -> tuple[bool, str]:
        """Регистрация нового пользователя."""
        try:
            self.connect()
            
            # Отправка команды регистрации
            data = f"REGISTER|{login}|{password}"
            self.socket.send(data.encode())
            
            # Получение ответа
            response = self.socket.recv(1024).decode()
            
            if response == "EXISTS":
                logger.warning(f"Пользователь {login} уже существует")
                return False, "Пользователь уже существует"
            elif response == "SUCCESS":
                self.login = login
                self.password = password
                return True, "Регистрация успешна"
            else:
                return False, "Ошибка при регистрации"
                
        except Exception as e:
            return False, f"Ошибка соединения: {e}"


    def exchange_keys(self) -> bool:
        try:

            # b - 64-битное нечетное число
            self.b = generate_odd_64bit()

            logger.info(f"Сгенерировано число b: {self.b}")
            
            self.socket.settimeout(5.0)
            
            data = self.socket.recv(4096).decode()

            # Получаем A, g, p от основного клиента
            self.A, self.g, self.p = map(int, data.split('|'))
            
            logger.info(f"Получены данные от хоста:")
            logger.info(f"A: {self.A}")
            logger.info(f"g: {self.g}")
            logger.info(f"p: {self.p}")
            
            # Вычисляем B = g^b mod p
            self.B = mod_exp(self.g, self.b, self.p)
            logger.info(f"Вычислено B: {self.B}")
            
            self.socket.send(str(self.B).encode())
            logger.info(f"Отправлено B: {self.B}")
            
            # Вычисляем сеансовый ключ K = A^b mod p
            self.K = mod_exp(self.A, self.b, self.p)
            logger.info(f"Вычислен сеансовый ключ K: {self.K}")
            
            self.rc4 = RC4(str(self.K))
            self.chat_window = ChatWindow(rc4=self.rc4, is_server=False, socket=self.socket)
            
            # Create message thread before showing window
            self.message_thread = MessageThread(self, self.chat_window)
            self.message_thread.message_received.connect(self.chat_window.display_received_message)
            self.message_thread.start()
            
            self.socket.settimeout(None)
            
            self.chat_window.show()
            return True
            
        except Exception as e:
            logger.error(f"Ошибка обмена ключами: {e}")
            return False
            
    def authenticate(self, login: str, password: str) -> tuple[bool, str]:
        """Аутентификация пользователя."""
        try:            
            # Проверяем соединение перед отправкой
            if not self.socket or self.socket._closed:
                self.connect()

            # Очищаем буфер сокета
            self.socket.settimeout(0.1)
            try:
                while True:
                    self.socket.recv(1024)
            except socket.timeout:
                pass
            finally:
                self.socket.settimeout(None)
            
            # Отправляем команду AUTH
            data = f"AUTH|{login}"
            self.socket.send(data.encode())
            
            response_a = self.socket.recv(1024).decode()
            logger.info(f"Захешированный sw от основного клиента: {response_a}")
            
            if response_a == "NOT_FOUND":
                logger.warning(f"Пользователь {login} не найден")
                return False, "Пользователь не найден"
                
            # Получаем хеш SW
            sw_hash = response_a

            # Хеш пароля
            password_hash = hash_md5(password)
            logger.info(f"Хеш пароля: {password_hash}")

            # Суперхеш = хеш(хеш SW + хеш пароля)
            final_hash = hash_md5(sw_hash + password_hash)
            logger.info(f"Суперхеш: {final_hash}")
            
            self.socket.send(final_hash.encode())
            
            auth_result = self.socket.recv(1024).decode()
            
            if auth_result == "SUCCESS":
                self.login = login
                self.password = password
                
                if self.exchange_keys():
                    logger.info("Аутентификация успешна")
                    return True, "Аутентификация успешна"
                return False, "Ошибка при обмене ключами"
                
            elif auth_result == "WRONG_PASSWORD":
                logger.warning("Неверный пароль")
                return False, "Неверный пароль"
            else:
                logger.warning("Ошибка аутентификации")
                return False, "Ошибка аутентификации"
        
        except Exception as e:
            logger.error(f"Ошибка аутентификации: {e}")
            return False, f"Ошибка аутентификации: {e}"
    
    def close(self):
        """Закрытие соединения."""
        if self.socket:
            self.socket.close()
            self.socket = None

from PyQt5.QtWidgets import QFileDialog

class ChatWindow(QMainWindow):
    message_received = pyqtSignal(str, str)  # encrypted, decrypted
    
    def __init__(self, rc4=None, is_server: bool = False, socket=None):
        super().__init__()
        self.rc4 = rc4 
        self.is_server = is_server
        self.socket = socket
        self.e = None
        self.n = None
        self.d = None
        self.file_path = None
        self.server_e = None
        self.server_n = None
        self.key_sent = False  # Флаг отправки ключей
        self.init_ui()
        self.sign_button.setEnabled(False)

    def update_sign_button_state(self):
        """Update sign button enabled state based on file and keys presence"""
        self.sign_button.setEnabled(
            self.file_path is not None and 
            self.server_e is not None and 
            self.server_n is not None and
            self.key_sent is True
        )

    def init_ui(self):
        self.setWindowTitle("Чат (Сервер)" if self.is_server else "Чат (Клиент)")
        self.setGeometry(100, 100, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Область чата
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        layout.addWidget(self.chat_area)
        
        # Поле ввода и кнопка отправки
        input_layout = QHBoxLayout()
        self.message_input = QTextEdit()
        self.message_input.setMaximumHeight(50)
        self.message_input.textChanged.connect(self.limit_text_length)  # Валидация на длину строки
        input_layout.addWidget(self.message_input)
        
        send_button = QPushButton("Отправить")
        send_button.clicked.connect(self.send_message)
        input_layout.addWidget(send_button)
        
        layout.addLayout(input_layout)
        
        # Кнопки для генерации и отправки ключей
        rsa_layout = QHBoxLayout()
        generate_button = QPushButton("Сгенерировать")
        generate_button.clicked.connect(self.generate_keys)
        rsa_layout.addWidget(generate_button)
        
        self.send_key_button = QPushButton("Отправить открытый ключ RSA")
        self.send_key_button.setEnabled(False)  # Отключаем кнопку "Отправить"
        self.send_key_button.clicked.connect(self.send_keys)
        rsa_layout.addWidget(self.send_key_button)
        
        layout.addLayout(rsa_layout)
        
        # Кнопки для загрузки и подписи файла
        file_layout = QHBoxLayout()
        load_file_button = QPushButton("Загрузить файл")
        load_file_button.clicked.connect(self.load_file)
        file_layout.addWidget(load_file_button)
        
        sign_button = QPushButton("Подписать и отправить")
        sign_button.clicked.connect(self.sign_file)
        self.sign_button = sign_button
        file_layout.addWidget(sign_button)
        
        layout.addLayout(file_layout)
        
        # Подключаем сигнал получения сообщения
        self.message_received.connect(self.display_received_message)

    def limit_text_length(self):
        """Ограничение длины текста в QTextEdit до 700 символов."""
        text = self.message_input.toPlainText()
        if len(text) > 700:
            self.message_input.setPlainText(text[:700])
            cursor = self.message_input.textCursor()
            cursor.setPosition(700)
            self.message_input.setTextCursor(cursor)
        
    def send_message(self):
        text = self.message_input.toPlainText().strip()
        if text:
            encrypted = self.rc4.encrypt(text)
            
            # Отображаем сообщение
            self.display_sent_message(encrypted, text)
            
            # Отправляем сообщение
            if self.socket:
                try:
                    # Явно указываем кодировку UTF-8
                    message = (encrypted + "\n").encode('utf-8')
                    self.socket.send(message)
                except Exception as e:
                    logger.error(f"Ошибка отправки сообщения: {e}")
                    self.close()
            
            # Очищаем поле ввода
            self.message_input.clear()
            
    def display_sent_message(self, encrypted: str, decrypted: str):
        cursor = self.chat_area.textCursor()
        cursor.movePosition(cursor.End)
        
        cursor.insertHtml('''
            <div style="margin: 10px 0; display: flex; align-items: center;">
                <div style="color: gray; font-size: 12px; margin-right: 10px;">Отправлено</div>
                <div style="
                    padding: 10px;
                    border-radius: 10px;
                    display: inline-block;
                ">
        ''')
        
        cursor.insertHtml(f'<div style="color: red; margin-bottom: 5px;">[{encrypted}]</div>')        
        cursor.insertHtml(f'<div>{decrypted}</div>')
        cursor.insertHtml('</div></div><br>')
        
        self.chat_area.verticalScrollBar().setValue(
            self.chat_area.verticalScrollBar().maximum()
        )

    def display_received_message(self, encrypted: str, decrypted: str):
        cursor = self.chat_area.textCursor()
        cursor.movePosition(cursor.End)
        
        cursor.insertHtml('''
            <div style="margin: 10px 0; display: flex; align-items: center;">
                <div style="color: gray; font-size: 12px; margin-right: 10px;">Получено</div>
                <div style="
                    padding: 10px;
                    border-radius: 10px;
                    display: inline-block;
                ">
        ''')
        
        cursor.insertHtml(f'<div style="color: red; margin-bottom: 5px;">[{encrypted}]</div>')
        cursor.insertHtml(f'<div>{decrypted}</div>')
        cursor.insertHtml('</div></div><br>')
                
        self.chat_area.verticalScrollBar().setValue(
            self.chat_area.verticalScrollBar().maximum()
        )

    def generate_keys(self):
        """Генерация ключей RSA."""
        from RSA import generate_keys
        (self.e, self.n), self.d = generate_keys()
        logger.info(f"Сгенерированы ключи RSA: e={self.e}, n={self.n}, d={self.d}")
        self.send_key_button.setEnabled(True)  # Включаем кнопку "Отправить"

    def send_keys(self):
        """Отправка открытого ключа серверу."""
        if self.e is not None and self.n is not None:
            public_key = f"KEYS|{self.e}|{self.n}"
            encrypted_key = self.rc4.encrypt(public_key)
            if self.socket:
                try:
                    self.socket.send((encrypted_key + "\n").encode())
                    self.key_sent = True
                    logger.info(f"Отправлен открытый ключ: e={self.e}, n={self.n}")
                except Exception as e:
                    logger.error(f"Ошибка отправки ключа")
                    self.close()

    def load_file(self):
        """Загрузка файла."""
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Загрузить файл", "", "Text Files (*.txt);", options=options
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    if len(content) > 700:
                        QMessageBox.warning(
                            self,
                            "Файл слишком большой",
                            "Файл должен содержать не более 700 символов."
                        )
                        return  
                    self.file_path = file_path
                    logger.info(f"Файл загружен: {file_path}")
                    self.update_sign_button_state()
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Ошибка при загрузке файла",
                    f"Не удалось открыть файл: {e}"
                )
                logger.error(f"Ошибка при загрузке файла {file_path}: {e}") 

    def handle_keys_received(self, e: int, n: int):
        """Handle received server keys"""
        self.server_e = e
        self.server_n = n
        self.update_sign_button_state()  


    def sign_file(self):
        """Подпись файла."""
        if self.file_path and self.d and self.n:
            with open(self.file_path, 'r') as file:
                file_data = file.read()

            # хеш файла H
            file_hash = hash_md5(file_data)
            logger.info(f"Хеш файла: {file_hash}")

            # X = H^d mod n
            signature = mod_exp(int(file_hash, 16), self.d, self.n)
            logger.info(f"Файл подписан: {self.file_path}, X: {signature}")
            
            # Объединяем данные в одну строку
            command = f"ECP|{file_data}|{signature}"
            
            # Зашифровываем команду
            encrypted_command = self.rc4.encrypt(command)
            
            # Отправляем зашифрованную команду на основной клиент
            if self.socket:
                try:
                    self.socket.send((encrypted_command + "\n").encode())
                    logger.info(f"Файл и подпись отправлены")
                except Exception as e:
                    logger.error(f"Ошибка отправки файла и подписи: {e}")

class MainWindow(QMainWindow):
    """Главное окно приложения."""
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.init_ui()
        self.show_registration()
        
    def init_ui(self):
        """Инициализация UI."""
        self.setWindowTitle('Клиент')
        self.setGeometry(100, 100, 300, 200)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
    def show_registration(self):
        """Показать окно регистрации."""
        self.clear_layout()
        
        self.layout.addWidget(QLabel('Регистрация'))
        
        self.login_input = QLineEdit()
        self.login_input.setPlaceholderText('Логин')
        self.layout.addWidget(self.login_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Пароль')
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)
        
        register_btn = QPushButton('Зарегистрироваться')
        register_btn.clicked.connect(self.register)
        self.layout.addWidget(register_btn)
        
        login_link = QPushButton('Уже есть аккаунт? Войти')
        login_link.clicked.connect(self.show_login)
        self.layout.addWidget(login_link)
        
    def show_login(self):
        """Показать окно входа."""
        self.clear_layout()
        
        self.layout.addWidget(QLabel('Вход'))
        
        self.login_input = QLineEdit()
        self.login_input.setPlaceholderText('Логин')
        self.layout.addWidget(self.login_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Пароль')
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)
        
        login_btn = QPushButton('Войти')
        login_btn.clicked.connect(self.login)
        self.layout.addWidget(login_btn)
        
        register_link = QPushButton('Создать аккаунт')
        register_link.clicked.connect(self.show_registration)
        self.layout.addWidget(register_link)
        
    def clear_layout(self):
        """Очистка layout."""
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
    def register(self):
        """Обработка регистрации."""
        login = self.login_input.text()
        password = self.password_input.text()
        
        valid, message = validate_credentials(login, password)
        if not valid:
            QMessageBox.warning(self, 'Ошибка', message)
            logger.error(f"Ошибка валидации: {message}")
            return
            
        success, message = self.client.register(login, password)
        if success:
            QMessageBox.information(self, 'Успех', message)
            logger.info(f"Пользователь с логином {login} и паролем {password} успешно зарегистрирован")
            self.show_login()
        else:
            QMessageBox.warning(self, 'Ошибка', message)
            logger.error(f"Ошибка регистрации: {message}")
        
    def login(self):
        """Обработка входа."""
        login = self.login_input.text()
        password = self.password_input.text()
        
        # valid, message = validate_credentials(login, password)
        # if not valid:
        #     QMessageBox.warning(self, 'Ошибка', message)
        #     return
            
        # Убираем лишний лог здесь
        success, message = self.client.authenticate(login, password)
        
        if success:
            self.hide()  # Hide auth window
        else:
            QMessageBox.warning(self, 'Ошибка', message)
            self.close()

def main():
    """Запуск приложения."""
    app = QApplication(sys.argv)
    client = Client()
    window = MainWindow(client)
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()