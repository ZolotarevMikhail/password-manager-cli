# -*- coding: utf-8 -*-
"""
Менеджер паролей с шифрованием
CLI-приложение: SQLite3 + Fernet (библиотека cryptography)
"""

import getpass
import hashlib
import os
import secrets
import string
import sys

from cryptography.fernet import Fernet

DB_FILE = "passwords.db"
KEY_FILE = ".key"

# ==================== РАБОТА С БАЗОЙ ДАННЫХ ====================

def init_db():
    """Создаёт таблицы, если их ещё нет."""
    import sqlite3
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS master_password (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            hash        TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            login       TEXT NOT NULL,
            password    TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def master_hash_exists():
    """Есть ли уже мастер-пароль в базе."""
    import sqlite3
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute("SELECT hash FROM master_password WHERE id = 1").fetchone()
    conn.close()
    return row is not None


def save_master_hash(password_hash):
    import sqlite3
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "INSERT OR REPLACE INTO master_password (id, hash) VALUES (1, ?)",
        (password_hash,))
    conn.commit()
    conn.close()


def get_master_hash():
    import sqlite3
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute("SELECT hash FROM master_password WHERE id = 1").fetchone()
    conn.close()
    return row[0] if row else None


def add_entry(name, login, encrypted_password):
    import sqlite3
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "INSERT INTO entries (name, login, password) VALUES (?, ?, ?)",
        (name, login, encrypted_password))
    conn.commit()
    conn.close()


def get_entries(name):
    """Все записи с таким названием (от новых к старым)."""
    import sqlite3
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT id, name, login, password FROM entries WHERE name = ? ORDER BY id DESC",
        (name,)).fetchall()
    conn.close()
    return rows


def list_entries():
    import sqlite3
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute("SELECT name, login FROM entries ORDER BY name").fetchall()
    conn.close()
    return rows


def delete_entry(name):
    import sqlite3
    conn = sqlite3.connect(DB_FILE)
    cur = conn.execute("DELETE FROM entries WHERE name = ?", (name,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    return deleted

# ==================== ШИФРОВАНИЕ ====================

def load_or_create_key():
    """Читает ключ из файла .key, если его нет — создаёт новый."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key


def encrypt(password: str, fernet: Fernet) -> str:
    return fernet.encrypt(password.encode()).decode()


def decrypt(encrypted: str, fernet: Fernet) -> str:
    return fernet.decrypt(encrypted.encode()).decode()

# ==================== ГЕНЕРАТОР ПАРОЛЕЙ ====================

def generate_password(length=16, use_upper=True, use_lower=True,
                      use_digits=True, use_special=True):
    """Случайный пароль из выбранных типов символов."""
    alphabet = ""
    if use_upper:
        alphabet += string.ascii_uppercase
    if use_lower:
        alphabet += string.ascii_lowercase
    if use_digits:
        alphabet += string.digits
    if use_special:
        alphabet += "!@#$%^&*"
    if not alphabet:
        return None
    return "".join(secrets.choice(alphabet) for _ in range(length))

# ==================== ИНТЕРФЕЙС ====================

def ask_yes_no(question, default="n"):
    """Вопрос с ответом да/нет. Enter = вариант по умолчанию."""
    suffix = " (Y/n): " if default == "y" else " (y/N): "
    answer = input(question + suffix).strip().lower()
    if not answer:
        answer = default
    return answer == "y"


def try_copy_to_clipboard(text):
    """Копирует в буфер обмена, если установлен pyperclip."""
    try:
        import pyperclip
        pyperclip.copy(text)
        print("Пароль скопирован в буфер обмена!")
    except ImportError:
        print("Для копирования в буфер обмена установите: pip install pyperclip")


def add_password_flow(fernet):
    print("=== Добавление нового пароля ===")
    name = input("Введите название/откуда (например, 'Google'): ").strip()
    if not name:
        print("Название не может быть пустым.")
        return
    login = input("Введите логин: ").strip()
    if ask_yes_no("Хотите сгенерировать пароль?"):
        password = generate_password_flow()
        if password is None:
            return
    else:
        password = getpass.getpass("Введите пароль (ввод скрыт): ")
    if not password:
        print("Пароль не может быть пустым.")
        return
    add_entry(name, login, encrypt(password, fernet))
    print(f"Пароль для '{name}' успешно добавлен!")


def generate_password_flow():
    print("=== Генерация пароля ===")
    try:
        raw = input("Длина пароля (8-64, по умолчанию 16): ").strip()
        length = int(raw) if raw else 16
    except ValueError:
        print("Нужно ввести число.")
        return None
    if not 8 <= length <= 64:
        print("Длина должна быть от 8 до 64.")
        return None
    use_upper = ask_yes_no("Заглавные буквы (A-Z)?", default="y")
    use_lower = ask_yes_no("Строчные буквы (a-z)?", default="y")
    use_digits = ask_yes_no("Цифры (0-9)?", default="y")
    use_special = ask_yes_no("Специальные символы (!@#$%^&*)?")
    password = generate_password(length, use_upper, use_lower,
                                 use_digits, use_special)
    if password is None:
        print("Нужно выбрать хотя бы один тип символов.")
        return None
    print(f"\nСгенерированный пароль: {password}")
    try_copy_to_clipboard(password)
    return password


def get_password_flow(fernet):
    print("=== Получение пароля ===")
    name = input("Введите название: ").strip()
    entries = get_entries(name)
    if not entries:
        print(f"Записи с названием '{name}' не найдены.")
        return
    entry_id, _, login, encrypted = entries[0]
    try:
        password = decrypt(encrypted, fernet)
    except Exception:
        print("Ошибка расшифровки (возможно, файл .key был заменён).")
        return
    print(f"Название: {name}")
    print(f"Логин:    {login}")
    print(f"Пароль:   {password}")
    if ask_yes_no("Скопировать пароль в буфер обмена?"):
        try_copy_to_clipboard(password)


def list_passwords_flow():
    print("=== Список всех паролей ===")
    entries = list_entries()
    if not entries:
        print("Сохранённых записей пока нет.")
        return
    print(f"{'Название':<25} {'Логин':<25}")
    print("-" * 50)
    for name, login in entries:
        print(f"{name:<25} {login:<25}")
    print(f"\nВсего записей: {len(entries)}")


def delete_password_flow():
    print("=== Удаление пароля ===")
    name = input("Введите название записи: ").strip()
    deleted = delete_entry(name)
    if deleted:
        print(f"Удалено записей: {deleted}")
    else:
        print(f"Записи с названием '{name}' не найдены.")


class PasswordManager:
    """Основной класс приложения."""

    def __init__(self):
        init_db()
        self.fernet = Fernet(load_or_create_key())

    def authenticate(self):
        """Вход: первый запуск — создание мастер-пароля, далее — проверка."""
        if master_hash_exists():
            stored = get_master_hash()
            while True:
                password = getpass.getpass("Введите мастер-пароль: ")
                if hashlib.sha256(password.encode()).hexdigest() == stored:
                    print("Аутентификация успешна!")
                    return True
                print("Неверный мастер-пароль. Попробуйте снова.")
        else:
            self.setup_master_password()
            return True
        return False

    def setup_master_password(self):
        """Настройка мастер-пароля при первом запуске."""
        print("Добро пожаловать! Это ваш первый запуск.")
        print("Создайте мастер-пароль для доступа к приложению.")
        while True:
            password = getpass.getpass("Введите мастер-пароль: ")
            if len(password) < 4:
                print("Пароль слишком короткий (минимум 4 символа).")
                continue
            confirm_password = getpass.getpass("Подтвердите мастер-пароль: ")
            if password == confirm_password:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                save_master_hash(password_hash)
                print("Мастер-пароль успешно создан!")
                break
            print("Пароли не совпадают. Попробуйте снова.")

    def run(self):
        if not self.authenticate():
            sys.exit(1)
        while True:
            print("\n" + "=" * 46)
            print("МЕНЕДЖЕР ПАРОЛЕЙ".center(46))
            print("=" * 46)
            print("1. Добавить новый пароль")
            print("2. Получить пароль")
            print("3. Список всех паролей")
            print("4. Удалить пароль")
            print("5. Сгенерировать пароль")
            print("6. Выход")
            print("=" * 46)
            choice = input("Выберите действие (1-6): ").strip()
            if choice == "1":
                add_password_flow(self.fernet)
            elif choice == "2":
                get_password_flow(self.fernet)
            elif choice == "3":
                list_passwords_flow()
            elif choice == "4":
                delete_password_flow()
            elif choice == "5":
                generate_password_flow()
            elif choice == "6":
                print("До свидания!")
                break
            else:
                print("Нет такого действия. Введите число от 1 до 6.")
            input("Нажмите Enter для продолжения...")


if __name__ == "__main__":
    try:
        PasswordManager().run()
    except (KeyboardInterrupt, EOFError):
        print("\nДо свидания!")
        sys.exit(0)