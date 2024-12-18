# logger.py
import sys
from datetime import datetime
from typing import TextIO

class Logger:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.initialize()
        return cls._instance
        
    def initialize(self):
        """Инициализация логгера."""
        self.log_file: TextIO = open('server.log', 'a', encoding='utf-8')
        
    def _write_log(self, level: str, message: str):
        """Запись лога в файл и вывод в консоль."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] [{level}] {message}"
        
        # Вывод в консоль
        print(log_message)
        
        # Запись в файл
        self.log_file.write(log_message + '\n')
        self.log_file.flush()
        
    def info(self, message: str):
        """Информационное сообщение."""
        self._write_log('INFO', message)
        
    def error(self, message: str):
        """Сообщение об ошибке."""
        self._write_log('ERROR', message)
        
    def warning(self, message: str):
        """Предупреждение."""
        self._write_log('WARNING', message)
        
    def __del__(self):
        """Закрытие файла при удалении объекта."""
        if hasattr(self, 'log_file'):
            self.log_file.close()

# Использование:
# logger = Logger()
# logger.info("Сервер запущен")
# logger.error("Ошибка подключения")
# logger.warning("Попытка несанкционированного доступа")