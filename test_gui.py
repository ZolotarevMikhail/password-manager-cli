# -*- coding: utf-8 -*-
"""Самопроверка GUI менеджера паролей на копии в отдельной папке
(не трогает настоящую базу паролей Mikhailа). Запуск: python3 test_gui.py"""

import shutil
import tempfile
import os

SRC = "/Users/nadezda/claudecode/Freelancer/PRJ2"


def main():
    tmp = tempfile.mkdtemp()
    shutil.copy(os.path.join(SRC, "password_manager.py"), tmp)
    shutil.copy(os.path.join(SRC, "gui.py"), tmp)
    os.chdir(tmp)  # база и ключ создадутся здесь, в чистой папке

    from gui import PasswordManagerApp, entry_by_id
    from password_manager import add_entry, decrypt, encrypt

    app = PasswordManagerApp()
    app.root.update()
    assert app.first_run is True, "в чистой папке должен предлагать создать мастер-пароль"

    # эмуляция создания мастер-пароля и переход к главному окну
    app.entry_master1.insert(0, "test1234")
    app.entry_master2.insert(0, "test1234")
    app._auth_submit()
    app.root.update()
    assert len(app.tree.get_children()) == 0
    print("Главное окно открылось OK")

    app.entry_length.delete(0, 'end')
    app.entry_length.insert(0, '20')
    app.var_special.set(True)
    app.generate()
    pwd = app.label_generate.cget("text")
    assert len(pwd) == 20 and any(c in "!@#$%^&*" for c in pwd)
    print("Генерация OK:", pwd)

    app.insert_generated()
    app.entry_name.insert(0, "Тест-сайт")
    app.entry_login.insert(0, "mishatest")
    app.add_password()
    app.root.update()
    rows = app.tree.get_children()
    assert len(rows) == 1, "запись должна появиться в таблице"
    print("Добавление в базу OK:", app.tree.item(rows[0])["values"])

    app.tree.selection_set(rows[0])
    app.copy_stored()
    assert app.root.clipboard_get() == pwd
    print("Копирование в буфер OK")

    entry_id = int(app.tree.item(rows[0])["values"][0])
    _, name, login, encrypted = entry_by_id(entry_id)
    assert decrypt(encrypted, app.fernet) == pwd
    print("Расшифровка OK")

    # --- поиск по логину (почте) ---
    add_entry("Другой сайт", "test@shop.ru",encrypt("shoppass99", app.fernet))

    # одна запись по уникальному логину → пароль сразу в буфер
    app.entry_search.delete(0, 'end')
    app.entry_search.insert(0, "test@shop.ru")
    app._apply_filter()
    app.root.update()
    assert len(app.tree.get_children()) == 1, "фильтр должен оставить одну строку"
    app._copy_first_match()
    assert app.root.clipboard_get() == "shoppass99"
    print("Поиск по логину с копированием OK")

    # несколько совпадений по общему запросу → подсказка, без копирования
    app.entry_search.delete(0, 'end')
    app.entry_search.insert(0, "test")  # совпадёт с "mishatest" и "test@shop.ru"
    app._copy_first_match()
    assert "Нашлось" in app.label_selected.cget("text")
    assert app.root.clipboard_get() == "shoppass99", "буфер не должен меняться"
    print("Спуск при нескольких совпадениях OK")

    # пустой поиск показывает всё
    app.entry_search.delete(0, 'end')
    app._apply_filter()
    assert len(app.tree.get_children()) == 2
    print("Сброс фильтра OK")

    app.entry_length.delete(0, 'end')
    app.entry_length.insert(0, '999')
    app.generate()  # предупреждение, без падения
    app.root.update()
    print("Проверки на ошибки OK")

    app.root.destroy()
    shutil.rmtree(tmp, ignore_errors=True)
    print("SMOKE TEST PASS")


if __name__ == "__main__":
    main()