# -*- coding: utf-8 -*-
"""Графический интерфейс менеджера паролей (tkinter).

Стиль как у напоминалки (PRJ1): заголовок, рамки-блоки,
таблица списком, внизу ряд быстрых кнопок.
Логика (база, шифрование, генератор) — из существующего модуля
password_manager.
"""

import hashlib
import hmac
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox

from cryptography.fernet import Fernet
from password_manager import (
    DB_FILE, KEY_FILE,
    init_db, master_hash_exists, get_master_hash, save_master_hash,
    add_entry, load_or_create_key, encrypt, decrypt, generate_password,
)


def entry_by_id(entry_id):
    """Одна запись целиком: (id, название, логин, зашифрованный пароль)."""
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute(
        "SELECT id, name, login, password FROM entries WHERE id = ?",
        (entry_id,)).fetchone()
    conn.close()
    return row


def delete_by_id(entry_id):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()


class PasswordManagerApp:
    """Главное окно: сначала вход по мастер-паролю, потом сам менеджер."""

    def __init__(self, root=None):
        self.root = root or tk.Tk()
        self.root.title("Менеджер паролей")
        self.root.geometry("900x640")
        self.root.minsize(760, 520)

        init_db()
        self.fernet = None  # ключ шифрования открываем после входа

        self._build_auth()

    # ==================== ВХОД ====================

    def _build_auth(self):
        """Окно входа: ввести мастер-пароль или создать его (первый запуск)."""
        self.first_run = not master_hash_exists()

        frame = tk.Frame(self.root)
        frame.pack(fill="both", expand=True)
        self.auth_frame = frame

        tk.Label(frame, text="Менеджер паролей",
                 font=("Arial", 16, "bold")).pack(pady=(60, 6))

        if self.first_run:
            sub = ("Первый запуск. Придумайте мастер-пароль —\n"
                   "им вы будете открывать своё хранилище.\n"
                   "Запишите его в надёжном месте: без него ничего не открыть!")
        else:
            sub = "Введите мастер-пароль, чтобы открыть хранилище."
        tk.Label(frame, text=sub, fg="#555555", justify="center").pack(pady=(0, 16))

        tk.Label(frame, text="Мастер-пароль:").pack()
        self.entry_master1 = tk.Entry(frame, show="*", width=28,
                                      justify="center")
        self.entry_master1.pack(pady=4)
        self.entry_master1.bind("<Return>", lambda e: self._auth_submit())

        if self.first_run:
            tk.Label(frame, text="Повторите пароль:").pack(pady=(8, 0))
            self.entry_master2 = tk.Entry(frame, show="*", width=28,
                                          justify="center")
            self.entry_master2.pack(pady=4)

        self.btn_auth = tk.Button(frame, text=(
            "Создать мастер-пароль" if self.first_run else "Открыть хранилище"),
            width=24, command=self._auth_submit)
        self.btn_auth.pack(pady=14)

        self.label_auth_error = tk.Label(frame, text="", fg="#c0392b")
        self.label_auth_error.pack()
        self.entry_master1.focus_set()

    def _auth_submit(self):
        """Проверка мастер-пароля или его создание при первом запуске."""
        password = self.entry_master1.get()
        if self.first_run:
            confirm = self.entry_master2.get()
            if len(password) < 4:
                self.label_auth_error.config(text="Минимум 4 символа.")
                return
            if password != confirm:
                self.label_auth_error.config(text="Пароли не совпадают.")
                return
            save_master_hash(
                hashlib.sha256(password.encode()).hexdigest())
            self._clear_window()
            self._unlock()
            return
        ok = hmac.compare_digest(
            hashlib.sha256(password.encode()).hexdigest(), get_master_hash())
        if ok:
            self._clear_window()
            self._unlock()
        else:
            self.label_auth_error.config(text="Неверный пароль.")
            self.entry_master1.delete(0, tk.END)

    def _clear_window(self):
        """Убирает содержимое окна (экран входа перед главным окном)."""
        for child in self.root.winfo_children():
            child.destroy()

    # ==================== ГЛАВНОЕ ОКНО ====================

    def _unlock(self):
        self.fernet = Fernet(load_or_create_key())
        self._build_main()

    def _build_main(self):
        self.root.title("Менеджер паролей")
        tk.Label(self.root, text="Менеджер паролей",
                 font=("Arial", 16, "bold")).pack(pady=(10, 4))

        # --- блок генерации ---
        gen = tk.LabelFrame(self.root, text=" Сгенерировать пароль ")
        gen.pack(fill="x", padx=12, pady=6)
        self.label_generate = tk.Label(gen, text="",
                                       font=("Courier", 12, "bold"))
        self.label_generate.pack(pady=(8, 2))

        opts = tk.Frame(gen)
        opts.pack(pady=2)
        self.var_upper = tk.BooleanVar(value=True)
        self.var_lower = tk.BooleanVar(value=True)
        self.var_digits = tk.BooleanVar(value=True)
        self.var_special = tk.BooleanVar(value=False)
        tk.Checkbutton(opts, text="Заглавные A-Z", variable=self.var_upper
                       ).pack(side="left", padx=6)
        tk.Checkbutton(opts, text="Строчные a-z", variable=self.var_lower
                       ).pack(side="left", padx=6)
        tk.Checkbutton(opts, text="Цифры 0-9", variable=self.var_digits
                       ).pack(side="left", padx=6)
        tk.Checkbutton(opts, text="Символы !@#$%^&*", variable=self.var_special
                       ).pack(side="left", padx=6)

        length_row = tk.Frame(gen)
        length_row.pack(pady=2)
        tk.Label(length_row, text="Длина (8–64):").pack(side="left")
        self.entry_length = tk.Entry(length_row, width=5)
        self.entry_length.pack(side="left", padx=6)
        self.entry_length.insert(0, "16")

        gen_buttons = tk.Frame(gen)
        gen_buttons.pack(pady=6)
        tk.Button(gen_buttons, text="Сгенерировать", width=16,
                  command=self.generate).pack(side="left", padx=6)
        tk.Button(gen_buttons, text="Скопировать", width=16,
                  command=self.copy_generated).pack(side="left", padx=6)
        tk.Button(gen_buttons, text="Вставить в форму ниже", width=22,
                  command=self.insert_generated).pack(side="left", padx=6)

        # --- блок добавления ---
        form = tk.LabelFrame(self.root, text=" Добавить пароль в базу ")
        form.pack(fill="x", padx=12, pady=6)

        tk.Label(form, text="Название:").grid(row=0, column=0, sticky="e",
                                              padx=8, pady=4)
        self.entry_name = tk.Entry(form, width=40)
        self.entry_name.grid(row=0, column=1, sticky="we", padx=8, pady=4)

        tk.Label(form, text="Логин:").grid(row=0, column=2, sticky="e",
                                           padx=8, pady=4)
        self.entry_login = tk.Entry(form, width=30)
        self.entry_login.grid(row=0, column=3, sticky="we", padx=8, pady=4)

        tk.Label(form, text="Пароль:").grid(row=1, column=0, sticky="e",
                                            padx=8, pady=4)
        self.entry_password = tk.Entry(form, width=40, show="*")
        self.entry_password.grid(row=1, column=1, sticky="we", padx=8, pady=4)

        show_row = tk.Frame(form)
        show_row.grid(row=1, column=2, columnspan=2, sticky="w", padx=8)
        self.var_show = tk.BooleanVar(value=False)
        tk.Checkbutton(show_row, text="Показать", variable=self.var_show,
                       command=self._toggle_show).pack(side="left")
        tk.Button(show_row, text="Добавить в базу", width=16,
                  command=self.add_password).pack(side="left", padx=6)

        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)

        # --- таблица сохранённых паролей ---
        table = tk.LabelFrame(self.root, text=" Список паролей ")
        table.pack(fill="both", expand=True, padx=12, pady=6)

        # Строка поиска: по названию ИЛИ логину (почте). Enter — быстрое копирование
        search_row = tk.Frame(table)
        search_row.pack(fill="x", padx=8, pady=(6, 2))
        tk.Label(search_row, text="Поиск (название или логин):").pack(side="left")
        self.entry_search = tk.Entry(search_row, width=32)
        self.entry_search.pack(side="left", padx=6)
        self.entry_search.bind("<KeyRelease>", self._apply_filter)
        self.entry_search.bind("<Return>", self._copy_first_match)
        tk.Label(search_row, text="Enter — скопировать пароль найденного",
                 fg="#888888").pack(side="left")

        columns = ("id", "name", "login")
        self.tree = ttk.Treeview(table, columns=columns, show="headings")
        for col, head, width in (("id", "№", 40), ("name", "Название", 200),
                                 ("login", "Логин", 240)):
            self.tree.heading(col, text=head)
            self.tree.column(col, width=width,
                             anchor="center" if col == "id" else "w")
        scroll = ttk.Scrollbar(table, orient="vertical",
                               command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, pady=(4, 0))
        scroll.pack(side="right", fill="y")

        # --- нижняя линейка быстрого доступа ---
        actions = tk.Frame(self.root)
        actions.pack(fill="x", padx=12, pady=(2, 4))
        tk.Button(actions, text="Показать пароль",
                  command=self.show_password).pack(side="left", padx=6)
        tk.Button(actions, text="Копировать пароль",
                  command=self.copy_stored).pack(side="left", padx=6)
        tk.Button(actions, text="Удалить",
                  command=self.delete_password).pack(side="left", padx=6)
        tk.Button(actions, text="Обновить список",
                  command=self.refresh).pack(side="left", padx=6)
        tk.Button(actions, text="Выход",
                  command=self.root.destroy).pack(side="right", padx=6)

        # Подсказка и строка статуса — видимый отклик на клики
        self.label_selected = tk.Label(self.root, text=(
            "Кликните по строке в списке, затем нажмите кнопку внизу"),
            fg="#888888")
        self.label_selected.pack(pady=(0, 6))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self.refresh()

    # ---------- действия ----------

    def _selected_entry(self):
        """Выбранная строка: запись целиком или None (с подсказкой)."""
        selected = self.tree.selection()
        if not selected:
            self.label_selected.config(
                text="Сначала выберите строку в списке — кликните по ней",
                fg="#c0392b")
            return None
        entry_id = int(self.tree.item(selected[0])["values"][0])
        return entry_by_id(entry_id)

    def _on_select(self, event=None):
        selected = self.tree.selection()
        if selected:
            values = self.tree.item(list(selected)[0])["values"]
            self.label_selected.config(
                text=f"Выбрано: №{values[0]} «{values[1]}»", fg="#333333")
        else:
            self.label_selected.config(text=(
                "Кликните по строке в списке, затем нажмите кнопку внизу"),
                fg="#888888")

    def generate(self):
        """Генерация пароля по выбранным галочкам и длине."""
        try:
            length = int(self.entry_length.get()) if self.entry_length.get() else 16
        except ValueError:
            length = -1
        if not 8 <= length <= 64:
            messagebox.showwarning("Менеджер паролей",
                                   "Длина должна быть числом от 8 до 64.")
            return
        password = generate_password(
            length,
            use_upper=self.var_upper.get(),
            use_lower=self.var_lower.get(),
            use_digits=self.var_digits.get(),
            use_special=self.var_special.get())
        if password is None:
            messagebox.showwarning("Менеджер паролей",
                                   "Нужно выбрать хотя бы один тип символов.")
            return
        self.generated = password
        self.label_generate.config(text=password)

    def copy_generated(self):
        """Копирует последний сгенерированный пароль в буфер обмена."""
        if not getattr(self, "generated", None):
            messagebox.showwarning("Менеджер паролей",
                                   "Сначала сгенерируйте пароль.")
            return
        self._to_clipboard(self.generated, "Сгенерированный пароль скопирован!")

    def insert_generated(self):
        """Подставляет сгенерированный пароль в поле формы добавления."""
        if not getattr(self, "generated", None):
            messagebox.showwarning("Менеджер паролей",
                                   "Сначала сгенерируйте пароль.")
            return
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, self.generated)
        self.label_selected.config(
            text="Пароль подставлен в поле «Пароль» — добавьте название и логин",
            fg="#1a6b1a")

    def add_password(self):
        name = self.entry_name.get().strip()
        login = self.entry_login.get().strip()
        password = self.entry_password.get()
        if not name:
            messagebox.showwarning("Менеджер паролей",
                                   "Введите название (например, Google).")
            return
        if not password:
            messagebox.showwarning("Менеджер паролей",
                                   "Введите пароль или вставьте сгенерированный.")
            return
        add_entry(name, login, encrypt(password, self.fernet))
        self.entry_name.delete(0, tk.END)
        self.entry_login.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)
        self.var_show.set(False)
        self._toggle_show()
        self.generated = ""
        self.label_generate.config(text="")
        self.refresh()

    def _toggle_show(self):
        self.entry_password.config(show="" if self.var_show.get() else "*")

    def show_password(self):
        """Показывает расшифрованный пароль выбранной записи в отдельном окне."""
        entry = self._selected_entry()
        if entry is None:
            return
        entry_id, name, login, encrypted = entry
        password = self._decrypt_or_error(encrypted)
        if password is None:
            return
        popup = tk.Toplevel(self.root)
        popup.title("Пароль — " + name)
        popup.geometry(f"+{self.root.winfo_x() + 200}+"
                       f"{self.root.winfo_y() + 120}")
        tk.Label(popup, text=f"{name} — {login}",
                 font=("Arial", 12, "bold")).pack(padx=20, pady=(14, 4))
        tk.Label(popup, text=password, font=("Courier", 13, "bold"),
                 fg="#1a6b1a").pack(padx=20, pady=6)
        btn_row = tk.Frame(popup)
        btn_row.pack(pady=12)
        tk.Button(btn_row, text="Копировать", width=14,
                  command=lambda: self._to_clipboard(
                      password, None, popup)).pack(side="left", padx=6)
        tk.Button(btn_row, text="Закрыть", width=10,
                  command=popup.destroy).pack(side="left", padx=6)

    def copy_stored(self):
        """Копирует пароль выбранной записи, не показывая его на экране."""
        entry = self._selected_entry()
        if entry is None:
            return
        entry_id, name, login, encrypted = entry
        password = self._decrypt_or_error(encrypted)
        if password is None:
            return
        self._to_clipboard(password, f"Пароль для «{name}» скопирован!")

    def delete_password(self):
        entry = self._selected_entry()
        if entry is None:
            return
        entry_id, name, login, _ = entry
        if messagebox.askyesno("Менеджер паролей",
                               f"Удалить запись «{name}»?"):
            delete_by_id(entry_id)
            self.refresh()

    # ---------- поиск по логину/почте ----------

    def _entries_full(self):
        """Все записи целиком: (id, название, логин, зашифрованный пароль)."""
        conn = sqlite3.connect(DB_FILE)
        rows = conn.execute(
            "SELECT id, name, login, password FROM entries"
        ).fetchall()
        conn.close()
        return rows

    def _matches(self, rows, query):
        """Строки, где запрос входит в название или логин (без регистра)."""
        query = query.strip().lower()
        if not query:
            return rows
        return [r for r in rows
                if query in r[1].lower() or query in (r[2] or "").lower()]

    def _apply_filter(self, event=None):
        """Мгновенный фильтр таблицы по полю поиска."""
        for row in self.tree.get_children():
            self.tree.delete(row)
        for row in self._matches(self._entries_full(),
                                 self.entry_search.get()):
            self.tree.insert("", "end", values=row[:3])

    def _copy_first_match(self, event=None):
        """Enter в поиске: одна запись — пароль сразу в буфер обмена.
        Несколько — подсказка уточнить; ноль — сообщение об этом."""
        query = self.entry_search.get().strip()
        matches = self._matches(self._entries_full(), query)
        if not matches:
            self.label_selected.config(
                text=f"По запросу «{query}» ничего не найдено",
                fg="#c0392b")
            return
        if len(matches) > 1:
            self.label_selected.config(
                text=(f"Нашлось {len(matches)} записей по «{query}» — "
                      "уточните запрос или выберите строку в списке"),
                fg="#c0392b")
            return
        entry_id, name, login, encrypted = matches[0]
        password = self._decrypt_or_error(encrypted)
        if password is None:
            return
        self._to_clipboard(password,
                           f"Пароль для «{name}» ({login}) скопирован!")

    def refresh(self):
        """Перечитывает базу и перерисовывает таблицу (с учётом поиска)."""
        if not hasattr(self, "tree"):
            return
        self._apply_filter()

    # ---------- служебное ----------

    def _decrypt_or_error(self, encrypted):
        """Расшифровка с понятным сообщением при неудаче."""
        try:
            return decrypt(encrypted, self.fernet)
        except Exception:
            messagebox.showerror(
                "Менеджер паролей",
                "Не удалось расшифровать. Возможно, файл .key был заменён.")
            return None

    def _to_clipboard(self, text, message=None, parent=None):
        target = parent or self.root
        target.clipboard_clear()
        target.clipboard_append(text)
        if message:
            self.label_selected.config(
                text=message + " — вставится по Cmd+V", fg="#1a6b1a")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    PasswordManagerApp().run()