import sqlite3
'''
Удаление данных из БД
'''
db_path = 'users.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute('DELETE FROM users')

conn.commit()

conn.close()

print("База данных очищена.")