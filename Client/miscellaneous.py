import hashlib
import random

def hash_md5(data: str) -> str:
    """
    MD5 хеширование строки.
    Принимает строку и возвращает её MD5 хеш в виде 32-символьной hex строки.
    
    Args:
        data (str): Входная строка для хеширования
        
    Returns:
        str: MD5 хеш в шестнадцатеричном представлении
    """
    # encode() конвертирует строку в байты, так как md5 работает с байтами
    # По умолчанию использует UTF-8 кодировку
    # Пример: "hello" -> b"hello"
    
    # hashlib.md5() создает объект хеширования MD5
    # После хеширования получаем 16-байтовое значение
    
    # hexdigest() конвертирует 16 байт хеша в 32-символьную строку в hex формате
    # Каждый байт представляется двумя hex цифрами
    # Пример: b"\x5d\x41\x40" -> "5d4140"
    return hashlib.md5(data.encode()).hexdigest()

import re

def validate_credentials(login: str, password: str) -> tuple[bool, str]:
    """Проверка валидности логина и пароля."""
    if len(login) < 5:
        return False, "Логин должен содержать минимум 5 символов"
    if len(login) > 30:
        return False, "Логин не должен превышать 30 символов"
    if not re.match(r'^[a-zA-Z0-9]+$', login):
        return False, "Логин должен содержать только латинские буквы и цифры"
    
    if len(password) < 5:
        return False, "Пароль должен содержать минимум 5 символов"
    if len(password) > 30:
        return False, "Пароль не должен превышать 30 символов"
    if not re.match(r'^[a-zA-Z0-9?!&]+$', password):
        return False, "Пароль должен содержать только латинские буквы, цифры и символы ?!&"
    if not re.search(r'[A-Z]', password):
        return False, "Пароль должен содержать хотя бы одну заглавную букву"
    if not re.search(r'[0-9]', password):
        return False, "Пароль должен содержать хотя бы одну цифру"
    
    return True, ""

def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Быстрое возведение в степень по модулю.
    base - основание
    exp - показатель степени 
    mod - модуль
    """
    # Особый случай - при модуле 1 всегда получаем 0
    # Любое число по модулю 1 всегда дает 0
    if mod == 1:
        return 0
    
    # Начальное значение результата
    result = 1
    # Приводим базу по модулю для оптимизации
    base = base % mod
    
    # Пока показатель степени не станет равным 0
    while exp > 0:
        # Если текущий бит показателя равен 1
        # (проверяем с помощью побитового И)
        if exp & 1:
            # Умножаем результат на текущую базу
            result = (result * base) % mod
            
        # Возводим базу в квадрат для следующей итерации
        base = (base * base) % mod
        # Сдвигаем показатель вправо (делим на 2)
        exp >>= 1
        
    return result

def generate_odd_64bit() -> int:
    """Генерация 64-битного нечетного числа."""
    num = random.getrandbits(64)
    if num % 2 == 0:
        num += 1
    return num