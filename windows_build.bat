@echo on

pyinstaller -F -w -i password_generator_icon.ico password_generator.py
pyinstaller -F -w -i password_generator_icon.ico password_from_bytes.py
