# client_main.py
import select
import socket
import sys
from datetime import datetime, timedelta

from typing import Optional, Tuple

from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTextEdit, QPushButton, QLabel, QMessageBox)
from PyQt5.QtGui import QColor, QTextCharFormat, QBrush
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
from PyQt5.QtCore import QThread, pyqtSignal

from database import UserDatabase

from miscellaneous import generate_sw, hash_md5, generate_odd_64bit, generate_prime_512bit, generate_generator, mod_exp
from RC4 import RC4

from logger import Logger
logger = Logger()


class ServerThread(QThread):
    """Поток для работы с сокетом."""
    client_connected = pyqtSignal()
    chat_ready = pyqtSignal(int)  # Новый сигнал для открытия чата
    message_received = pyqtSignal(str, str)  # Сигнал для полученных сообщений
    
    def __init__(self, server):
        super().__init__()
        self.server = server

    def run(self):
        self.server.wait_for_client(self)  # Передача ссылки на поток
        self.client_connected.emit()

class MainWindow(QMainWindow):
    """Главное окно приложения."""
    def __init__(self, server):
        super().__init__()
        self.server = server
        self.chat_window = None
        
        self.setWindowTitle("Хост")
        self.setGeometry(100, 100, 200, 100)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        self.status_label = QLabel("Ожидание подключения клиента...")
        self.layout.addWidget(self.status_label)
        
        self.server_thread = ServerThread(server)
        self.server_thread.client_connected.connect(self.on_client_connected)
        self.server_thread.chat_ready.connect(self.show_chat)
        self.server_thread.message_received.connect(self.on_message_received)
        self.server.message_box_signal.connect(self.show_message_box)
        self.server.close_window_signal.connect(self.close)  # Подключение сигнала для закрытия окна
        self.server_thread.start()
    
    def on_client_connected(self):
        """Обработка подключения клиента."""
        self.status_label.setText("Клиент подключен. Ожидание авторизации...")
    
    def show_chat(self, session_key):
        """Открытие окна чата."""
        self.chat_window = ChatWindow(rc4=self.server.rc4, 
                                    is_server=True, 
                                    socket=self.server.client_socket)
        self.chat_window.show()
        self.hide()
    
    def on_message_received(self, encrypted: str, decrypted: str):
        """Обработка полученного сообщения."""
        if self.chat_window:
            self.chat_window.message_received.emit(encrypted, decrypted)

    def show_message_box(self, title, message):
        """Отображение QMessageBox."""
        QMessageBox.information(self, title, message)

class ChatWindow(QMainWindow):
    message_received = pyqtSignal(str, str)  # encrypted, decrypted
    
    def __init__(self, session_key=None, is_server: bool = True, socket=None, rc4=None):
        super().__init__()
        self.rc4 = rc4 if rc4 else RC4(str(session_key))
        self.is_server = is_server
        self.socket = socket
        self.e = None
        self.n = None
        self.d = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Чат (Хост)" if self.is_server else "Чат (Клиент)")
        self.setGeometry(100, 100, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Поле ввода и кнопка отправки
        input_layout = QHBoxLayout()
        self.message_input = QTextEdit()
        self.message_input.setMaximumHeight(100)
        self.message_input.textChanged.connect(self.limit_text_length)  # Валидация на длину текста
        input_layout.addWidget(self.message_input)

        send_button = QPushButton("Отправить")
        send_button.clicked.connect(self.send_message)
        input_layout.addWidget(send_button)

        layout.addLayout(input_layout)

        # Область чата
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        layout.addWidget(self.chat_area)
        

        
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
                    # Явное указание UTF-8
                    message = (encrypted + "\n").encode('utf-8')
                    self.socket.send(message)
                except Exception as e:
                    logger.error(f"Ошибка отправки сообщения: Удаленный хост разорвал соединение")
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
        self.send_key_button.setEnabled(True)

    def send_keys(self):
        """Отправка открытого ключа клиенту."""
        if self.e is not None and self.n is not None:
            public_key = f"KEYS|{self.e}|{self.n}"
            encrypted_key = self.rc4.encrypt(public_key)
            if self.socket:
                try:
                    self.socket.send((encrypted_key + "\n").encode())
                    logger.info(f"Отправлен открытый ключ: e={self.e}, n={self.n}")
                except Exception as e:
                    logger.error(f"Ошибка отправки ключа")
                    self.close()

from PyQt5.QtCore import QObject, pyqtSignal

class Host(QObject):
    """Основной клиент."""
    message_box_signal = pyqtSignal(str, str)  # Заголовок, сообщение
    close_window_signal = pyqtSignal()  # Сигнал для закрытия окна

    def __init__(self, host: str = 'localhost', port: int = 12345):
        super().__init__()
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        self.client_socket = None
        self.db = UserDatabase('users.db')

        # Поля для криптографии
        self.a = None  # Секретное число основного клиента
        self.g = None  # Генератор группы
        self.p = None  # Простое число
        self.A = None  # Открытый ключ основного клиента
        self.K = None  # Сеансовый ключ
        self.client_e = None  # Открытый ключ клиента
        self.client_n = None  # Открытый ключ клиента

        # Поля для чата
        self.server_thread = None
        self.rc4 = None  # Объект для шифрования

    def wait_for_client(self, server_thread):
        """Ожидание подключения клиента."""
        self.server_thread = server_thread  # Сохраняем ссылку на поток
        self.client_socket, _ = self.socket.accept()
        self.handle_client()

    # В классе Host (server.py)
    def handle_client(self):
        """Обработка получаемых сообщений."""
        try:
            while True:
                try:
                    data = self.client_socket.recv(4096).decode()
                    if not data:
                        break
                    
                    
                    # Обработка авторизации
                    if data.startswith("AUTH|"):
                        _, login = data.split("|")
                        
                        if self.authenticate_user(login):
                            if self.exchange_keys():
                                logger.info("Сеансовый ключ установлен")
                        continue
                    
                    # Обработка регистрации
                    if data.startswith("REGISTER|"):
                        _, login, password = data.split("|")
                        if self.register_user(login, password):
                            self.client_socket.send(b"SUCCESS")
                        else:
                            self.client_socket.send(b"EXISTS")
                        continue

                    # Обработка зашифрованных сообщений
                    if self.rc4:
                        decrypted = self.rc4.encrypt(data.strip())
                        # Обработка команды KEYS (получения открытого ключа RSA)
                        if decrypted.startswith("KEYS|"):
                            _, e, n = decrypted.split("|")
                            self.client_e = int(e)
                            self.client_n = int(n)
                            logger.info(f"Получен открытый ключ клиента: e={e}, n={n}")
                            continue
                            
                        # Обработка команды ECP (проверка подписи особого файла)
                        if decrypted.startswith("ECP|"):
                            _, file_data, signature = decrypted.split("|")
                            if self.verify_signature(file_data, int(signature)):
                                decrypted = file_data
                            else:
                                continue
                            
                        # Обычное сообщение чата
                        if self.server_thread:
                            self.server_thread.message_received.emit(data.strip(), decrypted)
                            
                except socket.timeout:
                    continue
                        
        except Exception as e:
            pass
        finally:
            if self.client_socket:
                self.client_socket.close()

    def register_user(self, login: str, password: str) -> bool:
        """Обработка регистрации пользователя."""
        try:
            if self.db.find_user(login):
                self.client_socket.send(b"EXISTS")
                logger.info(f"Пользователь с логином {login} уже существует")
                self.close()
                self.close_window_signal.emit()
                logger.info("Соединение закрыто.")
                return False
                
            if self.db.add_user(login, password):
                logger.info(f"Пользователь с логином {login} и паролем {password} успешно зарегистрирован")
                self.client_socket.send(b"SUCCESS")
                return True
            else:
                self.client_socket.send(b"ERROR")
                logger.info(f"Ошибка при регистрации пользователя с логином {login}")
                self.close()
                self.close_window_signal.emit()
                logger.info("Соединение закрыто.")
                return False
                
        except Exception as e:
            logger.error(f"Ошибка при регистрации: {e}")
            self.client_socket.send(b"ERROR")
            return False

    def authenticate_user(self, login: str) -> bool:
        try:
            logger.info(f"Аутентификация пользователя: {login}")
            user = self.db.find_user(login)
            if not user:
                logger.info("Пользователь не найден. Отправка NOT_FOUND...")
                self.client_socket.send(b"NOT_FOUND")
                self.close()
                self.close_window_signal.emit()
                logger.info("Соединение закрыто.")
                return False

            logger.info("Пользователь найден. Генерация SW и установка времени...")
            sw = generate_sw()
            time = datetime.now() + timedelta(hours=24)
            logger.info(f"SW: {sw}, Time: {time}")
            
            self.db.update_user_auth(login, sw, time)
            
            sw_hash = hash_md5(sw)
            logger.info(f"Сгенерированный хеш sw: {sw_hash}")  
            self.client_socket.send(sw_hash.encode())
            
            client_hash = self.client_socket.recv(1024).decode()
            logger.info(f"Полученный хеш s от клиента: {client_hash}")

            
            stored_password = user[2]
            server_hash = hash_md5(hash_md5(sw) + stored_password)
            # server_hash = client_hash + stored_password
            logger.info(f"Хеш s` на основном клиенте: {server_hash}")
            
            # Проверка s` = s
            if client_hash != server_hash:
                logger.info("Неверный пароль. Отправка WRONG_PASSWORD...")
                self.client_socket.send(b"WRONG_PASSWORD")
                self.close()
                self.close_window_signal.emit()
                logger.info("Соединение закрыто.")
                return False
            
            logger.info("Аутентификация прошла успешно. Отправка SUCCESS...")
            self.client_socket.send(b"SUCCESS")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка авторизации: {e}")
            self.client_socket.send(b"ERROR")
            return False

    def exchange_keys(self):
        try:
            # 64-битное нечетное число a
            self.a = generate_odd_64bit()
            logger.info(f"Сгенерировано число a: {self.a}")

            # Генератор группы
            self.g = generate_generator()
            logger.info(f"Генератор g: {self.g}")

            # 512-битное простое число p
            self.p = generate_prime_512bit()
            logger.info(f"Сгенерировано простое число p: {self.p}")

            # A = g^a mod p
            self.A = mod_exp(self.g, self.a, self.p)
            logger.info(f"Вычислено число A: {self.A}")
            
            # Установим таймаут
            self.client_socket.settimeout(5.0)
            
            # Отправка A, g, p клиенту
            self.client_socket.send(f"{self.A}|{self.g}|{self.p}".encode())
            logger.info("A, g, p отправлены клиенту")
            
            # Получение B от клиента
            B = int(self.client_socket.recv(4096).decode())
            logger.info(f"Получено число B от клиента: {B}")
            
            # Вычисление K = B^a mod p
            self.K = mod_exp(B, self.a, self.p)
            logger.info(f"Вычислен сеансовый ключ K: {self.K}")
            
            # Инициализация RC4
            self.rc4 = RC4(str(self.K))
            
            # Восстанавливаем блокирующий режим
            self.client_socket.settimeout(None)
            
            # Сигнализируем о готовности чата
            self.server_thread.chat_ready.emit(self.K)
            
            return True
                
        except Exception as e:
            logger.error(f"Ошибка при обмене ключами: {e}")
            return False


    def verify_signature(self, file_data, signature):
        """Проверка подписи файла."""
        logger.info(f"Полученный файл: {file_data}")
        logger.info(f"Полученный X: {signature}")

        # H` - хеш файла
        file_hash = hash_md5(file_data)
        logger.info(f"Хеш файла: {file_hash}")

        # Z = X^e mod n
        calculated_hash = mod_exp(int(signature), self.client_e, self.client_n)

        # Проверка Z = H`
        if int(file_hash, 16) == calculated_hash:
            self.message_box_signal.emit('Подпись верна', 'Подпись файла верна.')
            logger.info(f"H`: {int(file_hash, 16)}")
            logger.info(f"Вычисленная (Z): {calculated_hash}")
            logger.info("Подпись файла верна.")
            return True
        else:
            self.message_box_signal.emit('Подпись неверна', 'Подпись файла неверна.')
            logger.warning("Подпись файла неверна.")
            logger.info(f"Полученная подпись: {signature}")
            logger.info(f"Вычисленная подпись (Z): {calculated_hash}")
            return False

    def close(self):
        """Закрытие основного клиента."""
        if self.client_socket:
            self.client_socket.close()
        if self.socket:
            self.socket.close()


def main():
    """Запуск приложения."""
    app = QApplication(sys.argv)
    server = Host()
    window = MainWindow(server)
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()