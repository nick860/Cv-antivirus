import _winreg as wimport osos.system("C:\Users\Admin\Music\poc-poc\OPEN\serverfile.py")key = w.OpenKey(w.HKEY_CURRENT_USER, 'Printers\Defaults\New Key #1', 0, w.KEY_ALL_ACCESS)info = w.QueryInfoKey(key)for ee in range(4):           name = w.EnumKey(key,0)   print name   w.DeleteKey(key, name)key = w.OpenKey(w.HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 0, w.KEY_ALL_ACCESS)w.DeleteValue(key, "NameOfNewValue")