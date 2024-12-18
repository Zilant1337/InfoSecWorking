# database.py
import sqlite3
from datetime import datetime
from typing import Optional, Tuple
from miscellaneous import hash_md5

from logger import Logger
logger = Logger()

class UserDatabase:
    def __init__(self, db_name: str):
        """Инициализация имени базы данных."""
        self.db_name = db_name
        self.conn = None
        self.cursor = None
        # Создаем таблицу при инициализации
        with self:
            self._create_table()

    def __enter__(self):
        """Открытие соединения при входе в контекст."""
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Закрытие соединения при выходе из контекста."""
        if self.conn:
            if exc_type is None:
                # Если не было исключений - сохраняем изменения
                self.conn.commit()
            self.conn.close()
            self.conn = None
            self.cursor = None

    def _create_table(self):
        """Создание таблицы users если она не существует."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                sw TEXT,
                time TIMESTAMP
            )
        ''')
        self.conn.commit()

    def add_user(self, login: str, password: str) -> bool:
        """Добавление нового пользователя с проверкой существования."""
        try:
            with self as db:
                # Проверяем существование пользователя
                db.cursor.execute('SELECT EXISTS(SELECT 1 FROM users WHERE login = ?)', (login,))
                exists = db.cursor.fetchone()[0]
                
                if exists:
                    return False
                
                # Добавляем пользователя с пустыми sw и time
                hashed_password = hash_md5(password)
                db.cursor.execute('''
                    INSERT INTO users (login, password, sw, time)
                    VALUES (?, ?, ?, ?)
                ''', (login, hashed_password, "", ""))
                logger.info(f"Пользователь с логином {login} и паролем {password} успешно зарегистрирован")
                logger.info(f"Захешированный пароль: {hashed_password}")
                return True
        except sqlite3.Error:
            return False

    def find_user(self, login: str) -> Optional[Tuple]:
        """Поиск пользователя по логину."""
        with self as db:
            db.cursor.execute('SELECT * FROM users WHERE login = ?', (login,))
            return db.cursor.fetchone()

    def get_sw(self, login: str) -> Optional[str]:
        """Получение значения sw пользователя."""
        with self as db:
            db.cursor.execute('SELECT sw FROM users WHERE login = ?', (login,))
            result = db.cursor.fetchone()
            return result[0] 

    def get_time(self, login: str) -> Optional[datetime]:
        """Получение времени регистрации пользователя."""
        with self as db:
            db.cursor.execute('SELECT time FROM users WHERE login = ?', (login,))
            result = db.cursor.fetchone()
            return datetime.fromisoformat(result[0]) 
    
    def update_user_auth(self, login: str, sw: str, time: datetime) -> bool:
        """Обновление SW и time для пользователя."""
        with self:
            self.cursor.execute('''
                UPDATE users 
                SET sw = ?, time = ?
                WHERE login = ?
            ''', (sw, time, login))
            logger.info(f"SW = {sw} и время = {time} для пользователя {login} обновлены")
            return True