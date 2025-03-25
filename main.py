import tkinter as tk
from tkinter import ttk, filedialog, messagebox, LEFT, Menu, PhotoImage, Text
import hashlib
import base64

import threading
import queue
import os

from cryptcrro.asymetric import crro
from cryptcrro.asymetric import rsa as crro_rsa
from cryptcrro.symetric import crro as scrro
from cryptcrro.utility import create_crro_block, parse_crro_public_block, parse_crro_private_block

if os.name == "posix":
    try:
        from tkfilebrowser import askopenfilename
    except Exception as e:
        print("Import Error", "tkfilebrowser failed to import file "
                                             "selection windows may not work on linux")
        askopenfilename = None

key_management_window1 = None
key_management_window = None
key_access_window = None
certificats_fenetre = None

cle = 1
key1 = None
cle_visible = 2
cle_visible2 = 2
type = 1
sign = 2
chiffrage = 2
rsa = 100
dark_mode = 3
file_output = os.path.join(os.path.expanduser('~'), 'Desktop')

evenement_changement_champ = threading.Event()


def create_smartcard():
    global key_access_window
    global chiffrage
    if key_access_window is not None:
        key_access_window.deiconify()
        return

    choice = messagebox.askyesno("Use already existing key?", "Do you want to use one of your existing key?\n If not a new key pair will be create")

    if choice:
        key_access_window1 = tk.Toplevel(fenetre)
        key_access_window1.title("Access to the key pair")

        def on_key_access_window_close():
            global key_access_window
            key_access_window1.destroy()
            key_access_window = None

        key_access_window1.protocol("WM_DELETE_WINDOW", on_key_access_window_close)

        label_nom = ttk.Label(key_access_window1, text="Name:", font=("Helvetica", 12))
        label_nom.grid(padx=120, pady=3)
        champ_nom = ttk.Entry(key_access_window1, width=50)
        champ_nom.grid(padx=5)

        label_password = ttk.Label(key_access_window1, text="Password:", font=("Helvetica", 12))
        label_password.grid(padx=120, pady=3)
        champ_password = ttk.Entry(key_access_window1, width=50, show="*")
        champ_password.grid()

        def access_key_pair3(event=None):
            global chiffrage
            password = champ_password.get().strip()

            password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

            double_hash = "Nom: " + champ_nom.get().strip()

            with open("key_pairs.txt", "r") as file:
                lines = file.readlines()
                found = False
                for i in range(0, len(lines), 5):
                    if lines[i].strip() == double_hash:
                        encrypted_public_key = lines[i + 3].strip().split(": ")[1]
                        encrypted_private_key = lines[i + 4].strip().split(": ")[1]

                        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'salt', 100000)

                        public_key = scrro.decrypt(key, encrypted_public_key.encode('utf-8')).decode('utf-8')
                        private_key = scrro.decrypt(key, encrypted_private_key.encode('utf-8')).decode('utf-8')

                        found = True
                        refresh_sha256_and_encryption_type()
                        on_key_access_window_close()
                        create_smartcard_file(private_key, public_key)
                        break

                if not found:
                    messagebox.showerror("Access denied", "incorrect name.")

            on_key_access_window_close()

        champ_password.bind("<Return>", access_key_pair3)
        bouton_access = ttk.Button(key_access_window1, text="Access", command=access_key_pair3)
        bouton_access.grid(pady=3)

    else:
        private_key, public_key = generate_keys()
        create_smartcard_file(private_key, public_key)


def create_smartcard_file(private_key, public_key):
    def encrypt_file_smartcard():
        output_path = os.path.join(os.path.expanduser('~'), 'Desktop')

        file_name = f'{str(champ_name.get().strip())}.crro_key'
        output_path = os.path.join(output_path, file_name)

        if os.path.exists(output_path):
            messagebox.showerror("Error", "The output file already exists.")
            return

        def bar_de_chargement():
            root = tk.Toplevel()
            root.title("Chargement")
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()

            window_width = 300
            window_height = 100
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2

            root.geometry(f"{window_width}x{window_height}+{x}+{y}")

            root.grab_set()
            progress_bar = ttk.Progressbar(root, orient="horizontal", length=window_width - 20, mode="indeterminate")
            progress_bar.pack(pady=20)
            progress_bar.start()

            def encrypt_and_close():
                key = pbkdf2(champ_password.get().strip().encode())
                cle_publique_bytes = str(public_key).encode()

                cle_priver_bytes = str(private_key).encode()

                prefixe_public = "Public key: ".encode()
                public_encrypted_data = scrro.encrypt(key, cle_publique_bytes)
                public_encrypted_data = public_encrypted_data + "\n".encode()
                public_key_and_prefixe = prefixe_public + public_encrypted_data

                private_encrypted_data = scrro.encrypt(key, cle_priver_bytes)
                prefixe_private = "Private key: ".encode()
                private_key_and_prefixe = prefixe_private + private_encrypted_data

                encrypted_key_with_prefixes = public_key_and_prefixe + private_key_and_prefixe

                with open(output_path, "wb") as encrypted_file:
                    encrypted_file.write(encrypted_key_with_prefixes)

                root.destroy()

                messagebox.showinfo("Smartcard", "Smartcard created successfully.")
                window2.destroy()

            root.protocol('WM_DELETE_WINDOW', root.destroy)  # Disable closing of the Toplevel window

            threading.Thread(target=encrypt_and_close).start()

        bar_de_chargement()

    window2 = tk.Toplevel()

    window2.title("Choose password for Smartcard")


    name_label = ttk.Label(window2, text="Enter a name:")
    name_label.pack()

    champ_name = ttk.Entry(window2, width=30)
    champ_name.pack()

    password_label = ttk.Label(window2, text="Enter a password:")
    password_label.pack()

    champ_password = ttk.Entry(window2, width=50, show="*")
    champ_password.pack(padx=5)

    generate_keypassword_button = ttk.Button(window2, text="Create Smartcard",
                                             command=lambda: encrypt_file_smartcard())
    generate_keypassword_button.pack(pady=7)


def use_smartcard():
    try:
        import psutil
    except ImportError:
        messagebox.showwarning("psutil missing",
                               "this feature cannot be use because psutil wasn't import at compile time")
        return
    all_file_with_extension = []
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts or 'usb' in partition.opts:
            path_wanted = partition.mountpoint
            for root, dirs, files in os.walk(path_wanted):
                for file in files:
                    if file.endswith(".crro_key"):
                        file_path = os.path.join(root, file)
                        all_file_with_extension.append(file_path)

    if len(all_file_with_extension) == 0:
        response = messagebox.askyesno(f"No Smartcard",
                                       "No Samrtcard found, searched manually?. ")
        if response:
            if os.name == "posix" and askopenfilename:
                file_path = askopenfilename(title="Select key file")
            else:
                file_path = filedialog.askopenfilename(title="Select key file")

    elif len(all_file_with_extension) > 1:
        messagebox.showinfo("several keys found", "several keys were found, please choose the key you want to use")
        if os.name == "posix" and askopenfilename:
            file_path = askopenfilename(title="Select key file",
                                               initialdir=os.path.dirname(all_file_with_extension[0]))
        else:
            file_path = filedialog.askopenfilename(title="Select key file",
                                               initialdir=os.path.dirname(all_file_with_extension[0]))
    else:
        response = messagebox.askyesno("Smartcard detected", f"A Key pair was found {os.path.basename(all_file_with_extension[0])}, use it? ")
        if not response:
            return

    def decrypt_file():
        def bar_de_chargement(Event=None):
            root = tk.Toplevel()
            root.title("Loading")

            # Obtenir les dimensions de l'écran
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()

            # Calculer les coordonnées pour centrer la fenêtre de chargement
            window_width = 300
            window_height = 100
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2

            root.geometry(f"{window_width}x{window_height}+{x}+{y}")

            root.grab_set()  # Mettre la fenêtre en premier plan

            progress_bar = ttk.Progressbar(root, orient="horizontal", length=window_width - 20, mode="indeterminate")
            progress_bar.pack(pady=20)
            progress_bar.start()

            def decrypt_and_close():
                key = pbkdf2(champ_password.get().strip().encode())
                key_entry_window.destroy()
                try:
                    with open(file_path, "r") as file:
                        encrypted_data = file.read().split("\n")

                        encrypted_public_key = encrypted_data[0].split(": ")[1]

                        encrypted_private_key = encrypted_data[1].split(": ")[1]

                    decrypted_public_key = scrro.decrypt(key, encrypted_public_key).decode()
                    decrypted_private_key = scrro.decrypt(key, encrypted_private_key).decode()

                    root.destroy()

                    only_private_key = messagebox.askyesno("Authorized access",
                                                           "Do you want to access only the private key?")

                    if only_private_key:
                        champ_clepriver.delete(0, tk.END)
                        champ_clepriver.insert(tk.END, decrypted_private_key)
                    else:
                        champ_clepublique.delete(0, tk.END)
                        champ_clepublique.insert(tk.END, decrypted_public_key)
                        champ_clepriver.delete(0, tk.END)
                        champ_clepriver.insert(tk.END, decrypted_private_key)

                except Exception as e:
                    root.destroy()
                    messagebox.showerror("Error",
                                         "The code is incorrect or Smartcard defective. Decryption failed.")
                    print(e)


            root.protocol('WM_DELETE_WINDOW', lambda: None)  # Disable closing of the Toplevel window

            threading.Thread(target=decrypt_and_close).start()

        key_entry_window = tk.Toplevel(window)
        key_entry_window.title("Access to the Smartcard")
        key_entry_window.geometry("370x70")

        password_label = ttk.Label(key_entry_window, text="Password:", font=("Helvetica", 12))
        password_label.pack(padx=120)
        champ_password = ttk.Entry(key_entry_window, width=50, show="*")
        champ_password.pack(padx=5)
        champ_password.focus()

        champ_password.bind("<Return>", bar_de_chargement)

        generate_keypassword_button = ttk.Button(key_entry_window, text="Access",
                                                 command=bar_de_chargement)

        generate_keypassword_button.pack()
        key_entry_window.attributes('-topmost', True)

    decrypt_file()


def enregistrer_parametres():
    parametres_file = "parametres.txt"

    # Ouvrir le fichier en mode écriture
    with open(parametres_file, "w") as file:
        # Écrire les paramètres dans le fichier
        global type
        file.write(f"Cle: {cle}\n")
        file.write(f"cle_visible: {cle_visible}\n")
        file.write(f"cle_visible2: {cle_visible2}\n")
        file.write(f"type: {type}\n")
        file.write(f"sign: {sign}\n")
        file.write(f"chiffrage: {chiffrage}\n")
        file.write(f"rsa: {rsa}\n")
        file.write(f"file_output; {file_output}\n")
        file.write(f"dark_mode: {dark_mode}\n")

    fenetre.quit()

viscle = cle_visible

viscle2 = cle_visible2

def open_file_encryption_window(output_entry_str):
    global window2

    if window2 is not None and window2.winfo_exists():
        window2.deiconify()
        return
    window.withdraw()

    def encrypt_file():
        window2.destroy()
        if os.name == "posix" and askopenfilename:
            file_path = askopenfilename(title="Select file to encrypt")
        else:
            file_path = filedialog.askopenfilename(title="Select file to encrypt")

        if not file_path:
            return

        print(file_path)
        nom_complet = os.path.basename(file_path)

        nouveau_nom_complet = nom_complet + ".crro"

        output_path_entry = output_entry_str
        if output_path_entry:
            output_path = os.path.join(output_path_entry, nouveau_nom_complet)

        else:

            output_path = os.path.join(os.path.dirname(__file__), nouveau_nom_complet)

        if os.path.exists(output_path):
            messagebox.showerror("Error", "The output file already exists.")
            return

        def bar_de_chargement():
            root = tk.Toplevel()
            root.title("Loading")

            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()

            window_width = 300
            window_height = 100
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2

            root.geometry(f"{window_width}x{window_height}+{x}+{y}")

            root.grab_set()  # Put window in front layer

            progress_bar = ttk.Progressbar(root, orient="horizontal", length=window_width - 20,
                                           mode="indeterminate")
            progress_bar.pack(pady=20)
            progress_bar.start()

            def encrypt_and_close():
                with open(file_path, "rb") as file:
                    file_data = file.read()

                encrypted_data = crypteraes(file_data)

                output_dir = os.path.dirname(output_path)
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                print(output_path)

                with open(output_path, "w") as encrypted_file:
                    encrypted_file.write(encrypted_data)

                root.destroy()

                messagebox.showinfo("Successful encryption", "The file was successfully encrypted.")

            root.protocol('WM_DELETE_WINDOW', root.destroy)  # Disable closing of the Toplevel window

            threading.Thread(target=encrypt_and_close).start()

        bar_de_chargement()

    def encrypt_file_symetric():
        password = champ_password.get()

        if os.name == "posix" and askopenfilename:
            file_path = askopenfilename(title="Select file to encrypt")
        else:
            file_path = filedialog.askopenfilename(title="Select file to encrypt")

        # On Gnu/linux os the filedialog doesn't  work, try to fix it by changing theme before opening the file dialogs
        """
        if os.name == "posix" and dark_mode == 1 or dark_mode == 0:

            current_theme = fenetre.tk.call("ttk::style", "theme", "use")

            fenetre.tk.call("ttk::style", "theme", "use", "clam")

            file_path = filedialog.askopenfilename(title="Select file to encrypt")

            fenetre.tk.call("set_theme", "light" if "light" in current_theme else "dark")

        else:
            file_path = filedialog.askopenfilename(title="Select file to encrypt") 
            """

        if not file_path:
            return
        nom_complet = os.path.basename(file_path)

        nouveau_nom_complet = nom_complet + ".crro"

        output_path_entry = output_entry_str
        if output_path_entry:
            output_path = os.path.join(output_path_entry, nouveau_nom_complet)

        else:
            output_path = os.path.join(os.path.dirname(__file__), nouveau_nom_complet)

        if os.path.exists(output_path):
            messagebox.showerror("Error", "The output file already exists.")
            return

        def bar_de_chargement():
            root = tk.Toplevel()
            root.title("Loading")

            # Obtenir les dimensions de l'écran
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()

            # Calculer les coordonnées pour centrer la fenêtre de chargement
            window_width = 300
            window_height = 100
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2

            root.geometry(f"{window_width}x{window_height}+{x}+{y}")

            root.grab_set()  # Mettre la fenêtre en premier plan

            progress_bar = ttk.Progressbar(root, orient="horizontal", length=window_width - 20,
                                           mode="indeterminate")
            progress_bar.pack(pady=20)
            progress_bar.start()

            def encrypt_and_close():
                key = pbkdf2(password.encode())

                with open(file_path, "rb") as file:
                    file_data = file.read()

                encrypted_data = scrro.encrypt(key, file_data)

                encrypted_data_with_tags = b"---BEGIN SCRRO MESSAGE---" + encrypted_data
                with open(output_path, "wb") as encrypted_file:
                    encrypted_file.write(encrypted_data_with_tags)

                root.destroy()

                messagebox.showinfo("Successful encryption", "The file was successfully encrypted.")

            root.protocol('WM_DELETE_WINDOW', root.destroy)  # Disable closing of the Toplevel window

            threading.Thread(target=encrypt_and_close).start()

        window2.destroy()
        bar_de_chargement()

    window2 = tk.Toplevel()

    window2.title("Files encryption program")

    def on_name_selected_menu1(event):
        selected_name = sign_combobox.get()

        line = selected_name
        close_or_not = 0
        open_key_access_window3(line, close_or_not)

    def update_checkboxes_sign():
        global sign
        global sign2
        global type
        global chiffrage
        global type2

        if checkbox1_var.get() == 0:
            sign_combobox.config(state="disabled")
            sign = 2
            sign2.set("Disable")
            label_typechiffrage2.config(text=sign2.get())
            # you need to refresh the type in case of another type of jey than the encrypt one
            refresh_sha256_and_encryption_type()
            refresh_check_box()

        else:
            sign_combobox.config(state="enabled")

            sign = 1
            sign2.set("Enable")
            label_typechiffrage2.config(text=sign2.get())
            refresh_sha256_and_encryption_type()
            refresh_check_box()

    def update_checkboxes_encrypt():
        global sign
        global sign2
        global type
        global chiffrage
        global type2
        if checkbox2_var.get() == 0:

            encrypt_combobox.config(state="disabled")
            type = 4
            chiffrage = 2
            type2.set("Disable")
            label_typechiffrage2.config(text=type2.get())
            refresh_sha256_and_encryption_type()
            refresh_check_box()

        else:
            encrypt_combobox.config(state="enabled")
            type = 1
            chiffrage = 2
            type2.set("Enable")
            label_typechiffrage2.config(text=type2.get())
            refresh_sha256_and_encryption_type()
            refresh_check_box()

    with open("registre.txt", "r") as fichier:
        contenu = fichier.readlines()
        i = 0  # Utilisé pour suivre la position actuelle dans le contenu
        entry_noms_pu = []
        while i < len(contenu):
            if contenu[i].startswith("Nom:"):
                nom = contenu[i].split(": ")[1].strip()  # Obtenir le nom correctement
                entry_noms_pu.append(nom)

                if i + 1 < len(contenu) and contenu[i + 1].startswith("Cle publique:"):
                    publique = contenu[i + 1].split(": ")[1].strip()  # Obtenir la clé publique correctement

                    # Passer à la ligne suivante après avoir traité le nom et la clé
                    i += 2
                else:
                    # Si la clé publique n'est pas trouvée, passer à la ligne suivante
                    i += 1
            else:
                # Passer à la ligne suivante si la ligne ne commence pas par "Nom:"
                i += 1

    with open("registre.txt", "r") as fichier:
        contenu = fichier.readlines()

        entry_noms_pu = []
        for line in contenu:
            if line.startswith("Nom:"):
                name = line.split(": ")[1].strip()
                entry_noms_pu.append(name)

    with open("key_pairs.txt", "r") as fichier:
        contenu = fichier.readlines()
        entry_noms = []
        for line in contenu:
            if line.startswith("Nom:"):
                name = line.split(": ")[1].strip()
                entry_noms.append(name)

    def recherche_clepublique(event):
        with open("registre.txt", "r") as fichier:
            contenu = fichier.readlines()
            i = 0  # Utilisé pour suivre la position actuelle dans le contenu
            selected_name = encrypt_combobox.get()
            entry_noms_pu = []
            for ligne in contenu:
                if ligne.startswith("Nom: " + selected_name):
                    nom = ligne.split(": ")[1].strip()
                    entry_noms_pu.append(nom)
                    key = contenu[i + 1].split(": ")[1].strip()  # Ligne suivante

                    copier_cle_cocobox(key, nom)

                    # Passer à la ligne suivante après avoir traité le nom
                    i += 1
                else:
                    # Passer à la ligne suivante si la ligne ne commence pas par "Nom:"
                    i += 1

    frame_combobox = tk.Frame(window2)
    frame_combobox.grid(pady=8, padx=5)

    checkbox1_var = tk.IntVar()
    checkbox2_var = tk.IntVar()

    checkbox1 = ttk.Checkbutton(frame_combobox, text="Sign as :      ", variable=checkbox1_var,
                                command=update_checkboxes_sign)
    checkbox2 = ttk.Checkbutton(frame_combobox, text="Encrypt for :", variable=checkbox2_var,
                                command=update_checkboxes_encrypt)

    encrypt_combobox = ttk.Combobox(frame_combobox, values=entry_noms_pu, width=35)
    encrypt_combobox.grid(row=0, column=1)
    encrypt_combobox.bind("<<ComboboxSelected>>", recherche_clepublique)

    sign_combobox = ttk.Combobox(frame_combobox, values=entry_noms, width=35)
    sign_combobox.grid(row=1, column=1, pady=5)
    sign_combobox.bind("<<ComboboxSelected>>", on_name_selected_menu1)

    if sign == 1:
        checkbox1.state(["selected"])
    else:
        sign_combobox.config(state="disabled")

    if type != 4:
        checkbox2.state(["selected"])
    else:
        encrypt_combobox.config(state="disabled")

    checkbox2.grid(row=0, column=0)
    checkbox1.grid(row=1, column=0)


    encryptfile_button = ttk.Button(window2, text="Encrypt/sign file with key", command=lambda: encrypt_file())
    encryptfile_button.grid(pady=7)

    ou_label = ttk.Label(window2, text="Or")
    ou_label.grid()

    password_label = ttk.Label(window2, text="Password :")
    password_label.grid()

    champ_password = ttk.Entry(window2, width=20, show="*")
    champ_password.grid()

    generate_keypassword_button = ttk.Button(window2, text="Encrypt with current password",
                                             command=lambda: encrypt_file_symetric())
    generate_keypassword_button.grid(pady=7)


def pbkdf2(password: bytes):
    key = hashlib.pbkdf2_hmac(
        "sha256", password=password,
        salt=b"CRRO_Encryption", iterations=4000
    )
    return key


def open_file_decryption_window(output_entry_str):
    global window2
    global window_file_decryption

    if window_file_decryption is not None and window_file_decryption.winfo_exists():
        window_file_decryption.deiconify()
        return
    window.withdraw()

    def decrypt_file(output_path):

        def on_name_selected_menu1(event):
            selected_name = sign_combobox.get()

            line = selected_name
            close_or_not = 0
            open_key_access_window3(line, close_or_not)

        def update_checkboxes_sign():
            global sign
            global sign2
            global type
            global chiffrage
            global type2

            if checkbox1_var.get() == 0:
                encrypt_combobox.config(state="disabled")
                sign = 2
                sign2.set("Disable")
                label_typechiffrage2.config(text=sign2.get())
                # you need to refresh the type in case of another type of jey than the encrypt one
                refresh_sha256_and_encryption_type()
                refresh_check_box()

            else:
                encrypt_combobox.config(state="enabled")

                sign = 1
                sign2.set("Enable")
                label_typechiffrage2.config(text=sign2.get())
                refresh_sha256_and_encryption_type()
                refresh_check_box()

        def update_checkboxes_encrypt():
            global sign
            global sign2
            global type
            global chiffrage
            global type2
            if checkbox2_var.get() == 0:

                sign_combobox.config(state="disabled")
                type = 4
                chiffrage = 2
                type2.set("Disable")
                label_typechiffrage2.config(text=type2.get())
                refresh_sha256_and_encryption_type()
                refresh_check_box()

            else:
                sign_combobox.config(state="enabled")
                type = 1
                chiffrage = 2
                type2.set("Enable")
                label_typechiffrage2.config(text=type2.get())
                refresh_sha256_and_encryption_type()
                refresh_check_box()

        with open("registre.txt", "r") as fichier:
            contenu = fichier.readlines()
            i = 0  # Utilisé pour suivre la position actuelle dans le contenu
            entry_noms_pu = []
            while i < len(contenu):
                if contenu[i].startswith("Nom:"):
                    nom = contenu[i].split(": ")[1].strip()  # Obtenir le nom correctement
                    entry_noms_pu.append(nom)

                    if i + 1 < len(contenu) and contenu[i + 1].startswith("Cle publique:"):
                        publique = contenu[i + 1].split(": ")[1].strip()  # Obtenir la clé publique correctement

                        # Passer à la ligne suivante après avoir traité le nom et la clé
                        i += 2
                    else:
                        # Si la clé publique n'est pas trouvée, passer à la ligne suivante
                        i += 1
                else:
                    # Passer à la ligne suivante si la ligne ne commence pas par "Nom:"
                    i += 1

        def recherche_clepublique(event):
            with open("registre.txt", "r") as fichier:
                contenu = fichier.readlines()
                i = 0  # Utilisé pour suivre la position actuelle dans le contenu
                selected_name = encrypt_combobox.get()
                entry_noms_pu = []
                for ligne in contenu:
                    if ligne.startswith("Nom: " + selected_name):
                        nom = ligne.split(": ")[1].strip()
                        entry_noms_pu.append(nom)
                        key = contenu[i + 1].split(": ")[1].strip()  # Ligne suivante

                        copier_cle_cocobox(key, nom)

                        # Passer à la ligne suivante après avoir traité le nom
                        i += 1
                    else:
                        # Passer à la ligne suivante si la ligne ne commence pas par "Nom:"
                        i += 1

        def get_password_and_decrypt(Event=None):
            password = champ_password.get()
            key = pbkdf2(password.encode())
            decrypt_file_symetric(key, output_path)


        with open(file_path, "rb") as file:  # was in str but let's try with bytes
            file_data = file.read()

        window_file_decryption = tk.Toplevel()
        window_file_decryption.title("Files decryption program")

        if file_data.startswith(b"---BEGIN SCRRO MESSAGE---"):
            password_label = ttk.Label(window_file_decryption, text="Password :")
            password_label.grid()

            champ_password = ttk.Entry(window_file_decryption, width=25, show="*")
            champ_password.grid(padx=20)
            champ_password.focus_set()

            generate_keypassword_button = ttk.Button(window_file_decryption, text="Decrypt",
                                                     command=lambda: get_password_and_decrypt())
            generate_keypassword_button.grid(pady=7)

            champ_password.bind("<Return>", get_password_and_decrypt)

        else:

            frame_combobox = tk.Frame(window_file_decryption)
            frame_combobox.grid(pady=8, padx=5)

            sign_combobox = ttk.Combobox(frame_combobox, value=entry_noms, width=35)
            sign_combobox.grid(row=0, column=1, pady=5)
            sign_combobox.bind("<<ComboboxSelected>>", on_name_selected_menu1)

            checkbox1_var = tk.IntVar()
            checkbox2_var = tk.IntVar()

            checkbox1 = ttk.Checkbutton(frame_combobox, text="Decrypt with  :", variable=checkbox2_var,
                                        command=update_checkboxes_encrypt)
            checkbox2 = ttk.Checkbutton(frame_combobox, text="Check sign for:", variable=checkbox1_var,
                                        command=update_checkboxes_sign)

            encrypt_combobox = ttk.Combobox(frame_combobox, values=entry_noms_pu, width=35)
            encrypt_combobox.grid(row=1, column=1)
            encrypt_combobox.bind("<<ComboboxSelected>>", recherche_clepublique)

            if sign == 1:
                checkbox2.state(["selected"])
            else:
                encrypt_combobox.config(state="disabled")

            if type != 4:
                checkbox1.state(["selected"])
            else:
                sign_combobox.config(state="disabled")

            checkbox1.grid(row=0, column=0)
            checkbox2.grid(row=1, column=0)

            encryptfile_button = ttk.Button(window_file_decryption, text="Decrypt/check sig file",
                                            command=lambda: bar_de_chargement())
            encryptfile_button.grid(pady=7)


        def bar_de_chargement():
            root = tk.Toplevel()
            root.title("Loading")

            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()


            window_width = 300
            window_height = 100
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2

            root.geometry(f"{window_width}x{window_height}+{x}+{y}")

            root.grab_set()

            progress_bar = ttk.Progressbar(root, orient="horizontal", length=window_width - 20,
                                           mode="indeterminate")
            progress_bar.pack(pady=20)
            progress_bar.start()

            def decrypt_and_close():
                window_file_decryption.destroy()
                with open(file_path, "rb") as file:
                    file_data = file.read()

                decrypt_data = decrypteraes(file_data)

                output_dir = os.path.dirname(output_path)
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                print(output_path)

                with open(output_path, "wb") as encrypted_file: # before with "wb"
                    encrypted_file.write(decrypt_data)

                root.destroy()

                messagebox.showinfo("Successful decryption", "The file was successfully decrypted.")

            root.protocol('WM_DELETE_WINDOW', root.destroy)  # Disable closing of the Toplevel window

            threading.Thread(target=decrypt_and_close).start()

        def decrypt_file_symetric(key, output_path):

            def bar_de_chargement():
                root = tk.Toplevel()
                root.title("Loading")

                screen_width = root.winfo_screenwidth()
                screen_height = root.winfo_screenheight()

                window_width = 300
                window_height = 100
                x = (screen_width - window_width) // 2
                y = (screen_height - window_height) // 2

                root.geometry(f"{window_width}x{window_height}+{x}+{y}")

                root.grab_set()  # Mettre la fenêtre en premier plan

                progress_bar = ttk.Progressbar(root, orient="horizontal", length=window_width - 20,
                                               mode="indeterminate")
                progress_bar.pack(pady=20)
                progress_bar.start()

                def decrypt_and_close():

                    with open(file_path, "rb") as file:
                        file_data = file.read().replace(b"---BEGIN SCRRO MESSAGE---", b"")

                    decrypted_data = scrro.decrypt(key, file_data)
                    with open(output_path, "wb") as decrypted_file:
                        decrypted_file.write(decrypted_data)

                    root.destroy()

                    messagebox.showinfo("Successful decryption", "The file was successfully decrypted.")

                root.protocol('WM_DELETE_WINDOW', root.destroy)  # Disable closing of the Toplevel window


                threading.Thread(target=decrypt_and_close).start()

            bar_de_chargement()
            window_file_decryption.destroy()

    if os.name == "posix" and askopenfilename:
        file_path = askopenfilename(title="Select file to decrypt")
    else:
        file_path = filedialog.askopenfilename(title="Select file to decrypt")

    if not file_path:
        return
    nom_complet = os.path.basename(file_path)
    nouveau_nom_complet = nom_complet.replace(".crro", "")

    output_path_entry = output_entry_str
    if output_path_entry:
        output_path = os.path.join(output_path_entry, nouveau_nom_complet)

    else:
        output_path = os.path.join(os.path.dirname(__file__), nouveau_nom_complet)

    if os.path.exists(output_path):
        messagebox.showerror("Error", "The output file already exists.")
        return

    decrypt_file(output_path)


def ouvrir_file():
    global window

    if window is not None and window.winfo_exists():
        window.deiconify()
        return


    window = tk.Toplevel()

    window.title("File encryption")

    key = None

    output_label = ttk.Label(window, text="Encryption/decryption output path :")
    output_label.pack()

    output_entry = ttk.Entry(window, width=30)

    global file_output
    output_entry.insert(0, file_output)
    output_entry.pack(padx=6)

    output_entry_str = output_entry.get().strip()


    def destroy_and_open_file_encryption_window(output_entry_str):
        global file_output
        file_output = output_entry.get().strip()
        open_file_encryption_window(output_entry_str)
        window.destroy()

    def destroy_and_open_file_decryption_window(output_entry_str):
        global file_output
        file_output = output_entry.get().strip()
        open_file_decryption_window(output_entry_str)
        window.destroy()

    encrypt_button = ttk.Button(window, text="Encrypt a file",
                                command=lambda: destroy_and_open_file_encryption_window(output_entry_str))
    encrypt_button.pack(pady=8)

    decrypt_button = ttk.Button(window, text="Decrypt a file",
                                command=lambda: destroy_and_open_file_decryption_window(output_entry_str))
    decrypt_button.pack(pady=8)

window_file_decryption = None
window2 = None
window = None

parametres = None


def adressebtc():
    adressebtc = tk.Toplevel(fenetre)

    adressebtc.title("support us")
    label_adressebtc = ttk.Label(adressebtc, text="Bitcoin Address:", font=("Helvetica", 12))
    label_adressebtc.pack()
    champ_adressebtc = ttk.Entry(adressebtc, width=50)
    champ_adressebtc.pack()
    champ_adressebtc.insert(0, "bc1q8j946v6gcnpumdjhdem2hhameh33fe4cy4xpqt")
    champ_adressebtc.pack(pady=10, padx=15)


def charger_parametres():
    parametres_file = "parametres.txt"
    if os.path.exists(parametres_file):
        with open(parametres_file, "r") as file:
            lignes = file.readlines()

            for ligne in lignes:
                if ligne.startswith("Cle:"):
                    cle_value = int(ligne.split(":")[1].strip())
                    global cle
                    cle = cle_value
                elif ligne.startswith("sign:"):
                    signature_value = int(ligne.split(":")[1].strip())
                    global sign
                    sign = signature_value
                elif ligne.startswith("cle_visible:"):
                    global cle_visible
                    cle_visible_value = int(ligne.split(":")[1].strip())
                    cle_visible = cle_visible_value
                elif ligne.startswith("type:"):
                    type_value = int(ligne.split(":")[1].strip())
                    global type
                    type = type_value
                elif ligne.startswith("chiffrage:"):
                    chiffrage_value = int(ligne.split(":")[1].strip())
                    global chiffrage
                    chiffrage = chiffrage_value
                elif ligne.startswith("rsa:"):
                    rsa_value = int(ligne.split(":")[1].strip())
                    global rsa
                    rsa = rsa_value
                elif ligne.startswith("cle_visible2:"):
                    type_value = int(ligne.split(":")[1].strip())
                    global cle_visible2
                    cle_visible2 = type_value
                elif ligne.startswith("file_output;"):
                    type_value = str(ligne.split(";")[1].strip())
                    global file_output
                    file_output = type_value
                elif ligne.startswith("dark_mode:"):
                    type_value = int(ligne.split(":")[1].strip())
                    global dark_mode
                    dark_mode = type_value


def ajouter_cle(entry_nom, entry_publique, frame_cles, on_configure):
    nom = entry_nom.get()

    if nom == "":
        return

    publique = entry_publique.get()

    hash_pub_key = sha256_hash(str(publique))

    show = f"{nom}  \n {hash_pub_key}\n"
    frame_cle = tk.Frame(frame_cles, pady=5)
    frame_cle.pack(fill=tk.X)  # Remplit l'espace horizontalement

    entry_name = tk.Entry(frame_cle, width=15)
    entry_name.insert(tk.END, nom)
    entry_name.pack(side=tk.LEFT, padx=(5, 0), pady=5)

    entry_cle = tk.Entry(frame_cle, width=40)
    entry_cle.insert(tk.END, hash_pub_key)
    entry_cle.pack(side=tk.LEFT, padx=5, pady=5)

    button_copier = ttk.Button(frame_cle, text="Use", width=2, command=lambda key=publique: copier_cle(key, nom))
    button_copier.pack(side=tk.LEFT, padx=5, pady=5)

    button_supprimer = ttk.Button(frame_cle, text="Delete", width=2,
                                  command=lambda frame=frame_cle, key=publique: confirmer_suppression(frame, key, nom))
    button_supprimer.pack(side=tk.LEFT, padx=5, pady=5)

    enregistrer_cle(nom, publique)
    on_configure(None)


def copier_cle(key, line):
    champ_clepublique.delete(0, tk.END)
    champ_clepublique.insert(tk.END, key)

    refresh_sha256_and_encryption_type()
    messagebox.showinfo("Access", "Access to the public key.")

    deuxieme_fenetre.destroy()


def copier_cle_cocobox(key, line):
    champ_clepublique.delete(0, tk.END)
    champ_clepublique.insert(tk.END, key)

    refresh_sha256_and_encryption_type()


def confirmer_suppression(frame_cle, key, nom):
    deuxieme_fenetre.lift()
    if messagebox.askyesno("Confirmation", "Are you sure you want to delete this public key?"):
        supprimer_cle(frame_cle, key, fenetre, nom)


def supprimer_cle(frame_cle, key, fenetre_principale, nom):
    frame_cle.destroy()
    supprimer_cle_fichier(key, nom)
    deuxieme_fenetre.lift()


def supprimer_cle_fichier(key, nom):
    with open("registre.txt", "r") as fichier:
        lignes = fichier.readlines()
    with open("registre.txt", "w") as fichier:
        for ligne in lignes:
            if f"Nom: {nom}" not in ligne:
                if f"Cle publique: {key}" not in ligne:
                    fichier.write(ligne)


def enregistrer_cle(nom, publique):
    with open("registre.txt", "a") as fichier:
        publique = str(publique)
        publique = publique.replace("(", "").replace(")", "").replace(",", "")
        fichier.write(f"Nom: {nom}\nCle publique: {publique}\n")


def charger_registre(frame_cles, parent_width):
    try:
        with open("registre.txt", "r") as fichier:
            contenu = fichier.readlines()
            i = 0  # Utilisé pour suivre la position actuelle dans le contenu
            while i < len(contenu):
                if contenu[i].startswith("Nom:"):
                    nom = contenu[i].split(": ")[1].strip()  # Obtenir le nom correctement

                    if i + 1 < len(contenu) and contenu[i + 1].startswith("Cle publique:"):
                        publique = contenu[i + 1].split(": ")[1].strip()  # Obtenir la clé publique correctement

                        hash_pub_key = sha256_hash(str(publique))

                        nom_publique = nom + "  " + hash_pub_key
                        frame = tk.Frame(frame_cles)
                        frame.pack(fill=tk.X, pady=5)

                        entry_name = tk.Entry(frame, width=12, highlightbackground="gray", highlightcolor="gray",
                                              highlightthickness=1)
                        entry_name.insert(tk.END, nom)  # Utiliser le nom ici
                        entry_name.pack(side=tk.LEFT, padx=(10, 0))

                        entry_cle = tk.Entry(frame, width=50, highlightbackground="gray", highlightcolor="gray",
                                             highlightthickness=1)
                        entry_cle.insert(tk.END, hash_pub_key)  # Utiliser le nom ici
                        entry_cle.pack(side=tk.LEFT)

                        def copier_cle_callback(key=publique, nom=nom):
                            deuxieme_fenetre.destroy()  # Utiliser les arguments par défaut
                            copier_cle(key, nom)

                        button_copier = ttk.Button(frame, text="Use", command=copier_cle_callback, width=10)
                        button_copier.pack(side=tk.LEFT, padx=5)

                        def supprimer_callback(key=publique, frame=frame, nom=nom):
                            confirmer_suppression(frame, key, nom)

                        button_supprimer = ttk.Button(frame, text="Delete", command=supprimer_callback, width=10)
                        button_supprimer.pack(side=tk.LEFT, padx=5)

                        # Passer à la ligne suivante après avoir traité le nom et la clé
                        i += 2
                    else:
                        # Si la clé publique n'est pas trouvée, passer à la ligne suivante
                        i += 1
                else:
                    # Passer à la ligne suivante si la ligne ne commence pas par "Nom:"
                    i += 1
    except FileNotFoundError:
        pass


def ouvrir_deuxieme_fenetre():
    global deuxieme_fenetre

    if deuxieme_fenetre is not None and deuxieme_fenetre.winfo_exists():
        deuxieme_fenetre.deiconify()
        return

    deuxieme_fenetre = tk.Toplevel(fenetre)
    deuxieme_fenetre.title("Public key management")

    parent_width = deuxieme_fenetre.winfo_width()

    deuxieme_fenetre.geometry("750x500")
    deuxieme_fenetre.resizable(False, False)

    frame_ajout = tk.Frame(deuxieme_fenetre)
    frame_ajout.pack(pady=10)

    label_nom = tk.Label(frame_ajout, text="Name :")
    label_nom.grid(row=0, column=0, padx=10)
    entry_nom = ttk.Entry(frame_ajout)
    entry_nom.grid(row=0, column=1, padx=10, pady=2)

    label_publique = tk.Label(frame_ajout, text="Public key :")
    label_publique.grid(row=1, column=0, padx=10)
    entry_publique = ttk.Entry(frame_ajout)
    entry_publique.grid(row=1, column=1, padx=10)

    scrollbar = ttk.Scrollbar(deuxieme_fenetre, orient=tk.VERTICAL)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    canvas = tk.Canvas(deuxieme_fenetre, yscrollcommand=scrollbar.set)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar.config(command=canvas.yview)

    frame_cles = tk.Frame(canvas)
    canvas.create_window((0, 0), window=frame_cles, anchor=tk.NW)

    def on_configure(event=None):
        canvas.configure(scrollregion=canvas.bbox("all"))

    button_ajouter = ttk.Button(frame_ajout, text="Add",
                                command=lambda: ajouter_cle(entry_nom, entry_publique, frame_cles, on_configure))
    button_ajouter.grid(row=2, columnspan=2, pady=10)

    charger_registre(frame_cles, parent_width)

    canvas.bind("<Configure>", on_configure)


deuxieme_fenetre = None

def generate_keys():
    global cle
    if cle == 5:

        private_key = crro.generate_private_key()

        public_key = crro.generate_public_key(private_key)

        return private_key, public_key

    else:

        if cle == 1:
            key_size = 1024
        elif cle == 2:
            key_size = 2048
        elif cle == 3:
            key_size = 3072
        else:
            key_size = 2048
        e = 65537  # e is often chosen as a small prime number for efficiency and security

        private_key, public_key = crro_rsa.generate_keys(key_size)

        return private_key, public_key


def generate_keypair_in_thread():
    global cle

    def thread_target():
        public_key, private_key = generate_keys()

        return public_key, private_key

    thread = threading.Thread(target=thread_target)
    thread.start()


def calculate_sha256_hash(text):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(text.encode('utf-8'))
    return sha256_hash.hexdigest()


def import_key_pair():
    if os.name == "posix" and askopenfilename:
        file_path = askopenfilename(title="Select the Key to import")
    else:
        file_path = filedialog.askopenfilename(title="Select the Key to import")

    if not file_path:
        return

    with open(file_path, "rb") as file:
        data = file.read()

    if data.startswith(b"-----BEGIN CRRO PRIVATE KEY BLOCK-----"):
        key_management_window1 = tk.Toplevel(fenetre)
        key_management_window1.title("import a key pair")

        label_nom = ttk.Label(key_management_window1, text="Name:", font=("Helvetica", 12))
        label_nom.pack()
        champ_nom = ttk.Entry(key_management_window1, width=45)

        file_name = os.path.basename(file_path).replace(".asc", "").replace("_SECRET", "")
        champ_nom.insert(0, file_name)
        champ_nom.pack(padx=5)

        label_password = ttk.Label(key_management_window1, text="Password:", font=("Helvetica", 12))
        label_password.pack()
        champ_password = ttk.Entry(key_management_window1, width=40, show="*")
        champ_password.focus()
        champ_password.pack()

        private_key, public_key, key_type = parse_crro_private_block(data)

        def save_key_pair(event=None):
            password = champ_password.get().strip()
            name = champ_nom.get().strip()
            # Vérifier si le mot de passe existe déjà dans le fichier
            with open("key_pairs.txt", "r+") as file:
                lines = file.readlines()
                double_hash = "Nom: " + name
                double_hash = double_hash.strip()
                for i in range(0, len(lines), 4):

                    if any(line.strip() == double_hash for line in lines):
                        messagebox.showwarning("Confirmation",
                                               "This name has already been used to saved a key pair. If you want to "
                                               "replace the existing key, delete the key manually.")
                        key_management_window1.focus_force()
                        champ_nom.focus()

                        return

            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'salt', 100000)

            public_key_str = str(public_key).replace("(", "").replace(")", "").replace(",", "").strip()
            private_key_str = str(private_key).replace("(", "").replace(")", "").replace(",", "").strip()

            encrypted_public_key = scrro.encrypt(key, public_key_str.encode('utf-8'))
            encrypted_private_key = scrro.encrypt(key, private_key_str.encode('utf-8'))

            key_hash = hashlib.sha256(public_key_str.encode('utf-8')).hexdigest()

            # Sauvegarde de la paire de clés chiffrées dans le fichier texte
            with open("key_pairs.txt", "a") as file:
                file.write(f"{double_hash}\n")
                file.write(f"typecle: {key_type}\n")
                file.write(f"hash: {key_hash}\n")
                file.write(f"Public Key: {encrypted_public_key.decode('utf-8')}\n")
                file.write(f"Private Key: {encrypted_private_key.decode('utf-8')}\n")

            messagebox.showinfo("Success", "The Key has Pair has been import successfully.")
            key_management_window1.destroy()
            refresh_all_certificates()

        button_save = ttk.Button(key_management_window1, text="Ok", command=save_key_pair)
        button_save.pack(pady=3)
        champ_password.bind("<Return>", save_key_pair)


    elif data.startswith(b"-----BEGIN CRRO PUBLIC KEY BLOCK-----"):
        public_key, key_type = parse_crro_public_block(data)
        public_key_str = str(public_key).replace("(", "").replace(")", "").replace(",", "").strip()

        key_management_window1 = tk.Toplevel(fenetre)
        key_management_window1.title("import a Public Key")

        label_nom = ttk.Label(key_management_window1, text="Name:", font=("Helvetica", 12))
        label_nom.pack()
        champ_nom = ttk.Entry(key_management_window1, width=45)

        file_name = os.path.basename(file_path).replace(".asc", "").replace("_PUBLIC", "")
        champ_nom.insert(0, file_name)
        champ_nom.focus()
        champ_nom.pack(padx=5)

        def save_public_key(event=None):
            name = champ_nom.get().strip()
            enregistrer_cle(name, public_key_str)
            messagebox.showinfo("Success", "The Public Key has been import successfully.")
            key_management_window1.destroy()
            update_combobox_public_key()

        button_save = ttk.Button(key_management_window1, text="Ok", command=save_public_key)
        button_save.pack(pady=3)
        champ_nom.bind("<Return>", save_public_key)
    else:
        raise ValueError("Error Key Tags")


def open_key_management_window():
    global key_management_window

    if key_management_window is not None:
        key_management_window.deiconify()
        return

    key_management_window = tk.Toplevel(fenetre)
    key_management_window.title("Key management")

    def on_key_management_window_close():
        global key_management_window
        key_management_window.destroy()
        key_management_window = None

    key_management_window.protocol("WM_DELETE_WINDOW", on_key_management_window_close)

    champ_clepublique = ttk.Entry(key_management_window, width=50)
    champ_clepublique.grid_forget()

    champ_clepriver = ttk.Entry(key_management_window, width=50)
    champ_clepriver.grid_forget()

    label_nom = ttk.Label(key_management_window, text="Name:", font=("Helvetica", 12))
    label_nom.grid(padx=20, row=0)
    champ_nom = ttk.Entry(key_management_window, width=45)
    champ_nom.grid(padx=20, row=1)

    label_password = ttk.Label(key_management_window, text="Password:", font=("Helvetica", 12))
    label_password.grid(row=2)
    champ_password = ttk.Entry(key_management_window, width=40, show="*")
    champ_password.grid(row=3)

    def bar_de_chargement():
        password = champ_password.get().strip()
        nom = champ_nom.get().strip()
        if not password:
            messagebox.showerror("Error", "please enter a name and password.")
            return
        root = tk.Toplevel()
        root.title("Generation of keys...")

        # Obtenir les dimensions de l'écran
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        # Calculer les coordonnées pour centrer la fenêtre de chargement
        window_width = 300
        window_height = 100
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2

        root.geometry(f"{window_width}x{window_height}+{x}+{y}")

        root.grab_set()  # Mettre la fenêtre en premier plan

        progress_bar = ttk.Progressbar(root, orient="horizontal", length=window_width - 20, mode="indeterminate")
        progress_bar.grid(pady=20)
        progress_bar.start()
        label_avercle = ttk.Label(root, text="Generating 3072-bit keys can take more than 3min",
                                  font=("Helvetica", 8))
        label_avercle.grid()
        root.update()
        root.after(2000, root.update)

        def thread_target():

            private_key, public_key = generate_keys()

            enregistrer_cle(nom, public_key)

            champ_clepublique.delete(0, tk.END)
            champ_clepriver.delete(0, tk.END)

            root.destroy()

            champ_clepublique.insert(tk.END,public_key)

            champ_clepriver.insert(tk.END,private_key)

            save_key_pair()

        thread = threading.Thread(target=thread_target)

        thread.start()

    bouton_generer = ttk.Button(key_management_window, text="Create a new key pair",
                                command=bar_de_chargement)
    bouton_generer.grid(pady=3, row=4)

    if cle == 5:
        label_type_cle = ttk.Label(key_management_window, text="Currently in mode : ECIES 256 bits",
                                   font=("Helvetica", 11))
        label_type_cle.grid(pady=10, row=5)
    else:

        if cle == 2:
            label_type_cle = ttk.Label(key_management_window, text="Currently in mode : RSA 2048 bits",
                                       font=("Helvetica", 11))
            label_type_cle.grid(pady=10, row=5)
        elif cle == 1:
            label_type_cle = ttk.Label(key_management_window, text="Currently in mode : RSA 1024 bits ",
                                       font=("Helvetica", 11))
            label_type_cle.grid(pady=10, row=5)

        elif cle == 3:
            label_type_cle = ttk.Label(key_management_window, text="Currently in mode : RSA 3072 bits",
                                       font=("Helvetica", 11))
            label_type_cle.grid(pady=10, row=5)

    bouton_advanced = ttk.Button(key_management_window, text="Key type",
                                 command=lambda: advanced_windows_fonction(label_type_cle))
    bouton_advanced.grid(pady=3, padx=3, sticky="e", row=6)

    def save_key_pair(event=None):
        public_key = champ_clepublique.get().strip()
        private_key = champ_clepriver.get().strip()
        password = champ_password.get().strip()

        if public_key and private_key and password:
            public_key = champ_clepublique.get().strip()
            private_key = champ_clepriver.get().strip()
            password = champ_password.get().strip()

            if public_key and private_key and password:
                password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

                hash_cle_priver = champ_clepublique.get().strip()
                hash_cle_priver = hashlib.sha256(hash_cle_priver.encode('utf-8')).hexdigest()

                global cle

                type_cle = "Unknow"

                if cle == 5:
                    type_cle = "ECIES 256 bits"
                else:

                    if cle == 1:
                        type_cle = "RSA 1024 bits"
                    elif cle == 2:
                        type_cle = "RSA 2048 bits"
                    elif cle == 3:
                        type_cle = "RSA 3072 bits"


                double_hash = champ_nom.get().strip()

                # Vérifier si le mot de passe existe déjà dans le fichier
                with open("key_pairs.txt", "r+") as file:
                    lines = file.readlines()
                    double_hash = "Nom: " + double_hash
                    double_hash = double_hash.strip()
                    for i in range(0, len(lines), 4):

                        if any(line.strip() == double_hash for line in lines):
                            # Le mot de passe existe déjà, demander à l'utilisateur de confirmer le remplacement
                            messagebox.showwarning("Confirmation",
                                                   "This name has already been used to saved a key pair. If you want to replace the existing key, delete the key manualy.")

                            return
                #A5E3F4D9C1E4638CA36753C5F59E0F2E116E6607
                # Le mot de passe n'existe pas encore, enregistrer la nouvelle paire de clés
                key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'salt', 100000)

                encrypted_public_key = scrro.encrypt(key, public_key.encode('utf-8'))
                encrypted_private_key = scrro.encrypt(key, private_key.encode('utf-8'))

                with open("key_pairs.txt", "a") as file:
                    file.write(f"{double_hash}\n")
                    file.write(f"typecle: {type_cle}\n")
                    file.write(f"hash: {hash_cle_priver}\n")
                    file.write(f"Public Key: {encrypted_public_key.decode('utf-8')}\n")
                    file.write(f"Private Key: {encrypted_private_key.decode('utf-8')}\n")

                messagebox.showinfo("Saved", "The key pair has been saved successfully.")
                key_management_window.withdraw()
                show_private_key_certificat()
            else:
                messagebox.showerror("Error", "Please complete all fields.")


advanced_windows = None


def advanced_windows_fonction(label_type_cle):
    global advanced_windows

    if advanced_windows is not None and advanced_windows.winfo_exists():
        advanced_windows.deiconify()
        return

    def update_checkboxes(checkbox):
        if checkbox == checkbox2:
            checkbox2.select()
            checkbox1.deselect()
            checkbox2.config(state='disabled')
            checkbox1.config(state='normal')
        elif checkbox == checkbox1:
            checkbox1.select()
            checkbox2.deselect()
            checkbox1.config(state='disabled')
            checkbox2.config(state='normal')

    def fermer_advanced(checkbox2_var, label_type_cle):
        global cle
        global type

        if checkbox1_var.get() == 1:
            if combobox1.get() == "1024 bits":
                cle = 1
                type = 1
                label_type_cle.config(text="Currently in mode : RSA 1024 bits")
            elif combobox1.get() == "2048 bits":
                cle = 2
                type = 1
                label_type_cle.config(text="Currently in mode : RSA 2048 bits")
            elif combobox1.get() == "3072 bits":
                cle = 3
                type = 1
                label_type_cle.config(text="Currently in mode : RSA 3072 bits")
        else:
            label_type_cle.config(text="Currently in mode : ECIES 256 bits")
            cle = 5

        advanced_windows.destroy()

    advanced_windows = tk.Toplevel(key_management_window)
    advanced_windows.title("key type")

    checkbox1_var = tk.IntVar()
    checkbox2_var = tk.IntVar()

    checkbox1 = tk.Checkbutton(advanced_windows, text="RSA", variable=checkbox1_var,
                               command=lambda: update_checkboxes(checkbox1))
    checkbox2 = tk.Checkbutton(advanced_windows, text="ECIES", variable=checkbox2_var,
                               command=lambda: update_checkboxes(checkbox2))

    checkbox1.grid(row=0, column=0, pady=5, sticky="W")
    checkbox2.grid(row=1, column=0, sticky="W")

    combo_values1 = ["1024 bits", "2048 bits", "3072 bits"]
    combobox1 = ttk.Combobox(advanced_windows, values=combo_values1, width=10)
    combobox1.grid(row=0, column=1, padx=10)

    if cle == 1:
        combobox1.set("1024 bits")
    elif cle == 2:
        combobox1.set("2048 bits")
    elif cle == 3:
        combobox1.set("3072 bits")

    combo_values2 = ["256 bits"]
    combobox2 = ttk.Combobox(advanced_windows, values=combo_values2, width=10)
    combobox2.grid(row=1, column=1, padx=10)

    # Définir une valeur par défaut pour le Combobox
    combobox2.set("256 bits")

    button = ttk.Button(advanced_windows, text="ok", command=lambda: fermer_advanced(checkbox2_var, label_type_cle))
    button.grid(row=2, pady=15, column=1, sticky="W")

    global type

    if type == 5:
        checkbox2.select()
        checkbox2.config(state='disabled')
    else:
        checkbox1.select()
        checkbox1.config(state='disabled')


def destroy_key_management_window():
    global key_management_window

    if key_management_window is not None:
        key_management_window.withdraw()


def destroy_key_access_window():
    global key_access_window

    if key_access_window is not None:
        key_access_window.withdraw()


def copy_result():
    result = champ_message.get("1.0", tk.END)
    if result:
        fenetre.clipboard_clear()
        fenetre.clipboard_append(str(result))


def ouvrir_type_chiffrage():
    global type_chiffrage
    # Vérifier si la deuxième fenêtre est déjà ouverte
    if type_chiffrage is not None and type_chiffrage.winfo_exists():
        type_chiffrage.deiconify()
        type_chiffrage.lift()
        return
    type_chiffrage = tk.Toplevel(fenetre)
    type_chiffrage.title("Parameters")

    def fenetreferme1():
        type_chiffrage.destroy()
        global type
        global chiffrage
        type = 1
        chiffrage = 2
        type2.set("Enable")
        label_typechiffrage2.config(text=type2.get())

    def fenetreferme2():
        type_chiffrage.destroy()
        global type
        global chiffrage
        type = 3
        chiffrage = 2
        type2.set("AES")
        label_typechiffrage2.config(text=type2.get())

    def fenetreferme3():
        type_chiffrage.destroy()
        global type
        global chiffrage
        type = 2
        chiffrage = 2
        type2.set("RSA")
        label_typechiffrage2.config(text=type2.get())

    def fenetreferme4():
        type_chiffrage.destroy()
        global type
        global chiffrage
        type = 4
        chiffrage = 2
        type2.set("Disable")
        label_typechiffrage2.config(text=type2.get())

    def fenetreferme5():
        type_chiffrage.destroy()
        global type
        global chiffrage
        type = 5
        chiffrage = 2
        type2.set("ecies")
        label_typechiffrage2.config(text=type2.get())

    label_taille = ttk.Label(type_chiffrage, text="Encryption Type :", font=("Helvetica", 12))
    label_taille.pack(pady=5)

    label_taille = ttk.Label(type_chiffrage, text="Hybrid Encryption (recommended) :", font=("Helvetica", 10))
    label_taille.pack(pady=5)

    label_taille = ttk.Label(type_chiffrage, text="On Prime Numbers :", font=("Helvetica", 8))
    label_taille.pack(pady=5)

    bouton_access = ttk.Button(type_chiffrage, text="AES + RSA", command=fenetreferme1)
    bouton_access.pack(ipady=2)

    label_taille = ttk.Label(type_chiffrage, text="On Elliptic Curve :", font=("Helvetica", 8))
    label_taille.pack(pady=5)

    bouton_access = ttk.Button(type_chiffrage, text="ecies + sign Ecdsa", command=fenetreferme5)
    bouton_access.pack(ipady=2)

    label_taille = ttk.Label(type_chiffrage, text="   ", font=("Helvetica", 8))
    label_taille.pack()

    label_taille = ttk.Label(type_chiffrage, text="Solo symetric and asymetric Encryption :", font=("Helvetica", 9))
    label_taille.pack(pady=5)

    bouton_access = ttk.Button(type_chiffrage, text="AES (sym)", width=9, command=fenetreferme2)
    bouton_access.pack()

    bouton_access = ttk.Button(type_chiffrage, text="RSA (asy)", width=8, command=fenetreferme3)
    bouton_access.pack(pady=3)

    label_taille = ttk.Label(type_chiffrage, text="   ", font=("Helvetica", 8))
    label_taille.pack()

    label_taille = ttk.Label(type_chiffrage, text="Without Encryption :", font=("Helvetica", 9))
    label_taille.pack()

    bouton_access = ttk.Button(type_chiffrage, text="no encryption", command=fenetreferme4)
    bouton_access.pack(pady=5, ipady=2)

    if type == 1:
        label_type_cle = ttk.Label(type_chiffrage, text="Currently in mode : AES + RSA", font=("Helvetica", 12))
        label_type_cle.pack(pady=10, padx=7)
    elif type == 3:
        label_type_cle = ttk.Label(type_chiffrage, text="Currently in mode : AES ", font=("Helvetica", 12))
        label_type_cle.pack(pady=10, padx=7)
    elif type == 2:
        label_type_cle = ttk.Label(type_chiffrage, text="Currently in mode : RSA ", font=("Helvetica", 12))
        label_type_cle.pack(pady=10, padx=7)
    elif type == 4:
        label_type_cle = ttk.Label(type_chiffrage, text="Currently in mode : Aucun chiffrement ",
                                   font=("Helvetica", 12))
        label_type_cle.pack(pady=10, padx=7)

    elif type == 5:
        label_type_cle = ttk.Label(type_chiffrage, text="Currently in mode : ecies + sign Ecdsa",
                                   font=("Helvetica", 12))
        label_type_cle.pack(pady=10, padx=7)

    def fermer_parametres():
        parametres.destroy()


type_chiffrage = None


def type_signature():
    global sign
    global sign2
    if sign == 1:
        sign = 2
        sign2.set("Disable")
        label_typechiffrage2.config(text=sign2.get())

    elif sign != 1:
        sign = 1
        sign2.set("Enable")
        label_typechiffrage2.config(text=sign2.get())

def sign_with_the_right_type(plaintext, file=False):
    private_key_str = champ_clepriver.get()

    if " " in private_key_str:  # mean a rsa private key
        private_key = tuple(map(int, champ_clepriver.get().split()))
        if file:
            return crro_rsa.sign(private_key, base64.urlsafe_b64encode(plaintext))
        else:
            return crro_rsa.sign(private_key, plaintext)

    else:  # mean an ecc private key
        private_key = int(champ_clepriver.get())
        if file:
            return crro.sign(private_key, base64.urlsafe_b64encode(plaintext))
        else:
            return crro.sign(private_key, plaintext)


def encrypt_with_the_right_type(plaintext, file=False):
    global sign
    if sign == 1:
        plaintext = plaintext.encode()

    public_key_str = champ_clepublique.get()
    if public_key_str.startswith("65537 "):  # mean a rsa public key
        public_key = tuple(map(int, champ_clepublique.get().split()))
        if file == True:
            return crro_rsa.encrypt(public_key,plaintext)
        else:
            return crro_rsa.encrypt(public_key, plaintext)

    else:  # mean an ecc public key
        public_key = tuple(map(int, champ_clepublique.get().split()))
        if file == True:
            return crro.encrypt(public_key, plaintext)
        else:
            return crro.encrypt(public_key, plaintext)


def crypteraes(file):
    ciphertext_all = "test"

    if type == 1 and not champ_clepublique.get():
        ouvrir_deuxieme_fenetre()
        return

    if type == 5 and not champ_clepublique.get():
        ouvrir_deuxieme_fenetre()
        return

    elif type == 2 and not champ_clepublique.get():
        ouvrir_deuxieme_fenetre()
        return

    if sign == 1 and not champ_clepriver.get():
        liste_certificat()

    else:

        def bar_de_chargement():
            root = tk.Toplevel()
            root.title("encryption...")

            # Obtenir les dimensions de l'écran
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()

            # Calculer les coordonnées pour centrer la fenêtre de chargement
            window_width = 300
            window_height = 100
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2

            root.geometry(f"{window_width}x{window_height}+{x}+{y}")

            root.grab_set()  # Mettre la fenêtre en premier plan

            progress_bar = ttk.Progressbar(root, orient="horizontal", length=window_width - 20, mode="indeterminate")
            progress_bar.pack(pady=20)
            progress_bar.start()

            def crypteraes_thread():
                global type
                global sign
                root.update()

                try:

                    if file != None:
                        ciphertext = file
                    else:
                        ciphertext = champ_message.get("1.0", tk.END).strip().encode()

                    if sign == 1:
                        if file != None:
                            ciphertext = sign_with_the_right_type(ciphertext, file=True)
                        else:
                            ciphertext = sign_with_the_right_type(ciphertext)

                    if type == 1:
                        if file != None:
                            ciphertext = encrypt_with_the_right_type(ciphertext)
                            ciphertext = f"---BEGIN CRRO FILE---\n{ciphertext}\n---END CRRO FILE---"
                        else:
                            ciphertext = encrypt_with_the_right_type(ciphertext)

                    if file != None:
                        return ciphertext
                    else:
                        champ_message.delete('1.0', tk.END)
                        champ_message.insert(tk.END, ciphertext)
                        return

                except Exception as e:
                    root.destroy()
                    messagebox.showerror("encryption failed", "encryption failed: " + str(e))

            if file != None:
                result_queue = queue.Queue()
                thread = threading.Thread(target=lambda q: q.put(crypteraes_thread()), args=(result_queue,))
                thread.start()
                thread.join()  # Attendre que le thread se termine
            else:
                threading.Thread(target=crypteraes_thread).start()

            fenetre.after(1, root.destroy)

            if file != None:
                # Récupérer le résultat de la file d'attente
                result = result_queue.get()

                print("thread", result)

            if file != None:
                return result

        data = bar_de_chargement()

    if file != None:
        return data


def sha256_hash(input_str):
    input_bytes = input_str.encode('utf-8')
    sha256_hash_obj = hashlib.sha256()
    sha256_hash_obj.update(input_bytes)
    hashed_str = sha256_hash_obj.hexdigest()
    return hashed_str


def check_sign_with_the_right_type(plaintext, file=False):
    public_key_str = champ_clepublique.get()

    if public_key_str.startswith("65537 "):  # mean a rsa public key
        public_key = tuple(map(int, champ_clepublique.get().split()))
        if file == True:
            print("plaintext", plaintext)
            return crro_rsa.check_signature(public_key, plaintext.decode())
        else:
            print("plaintext", plaintext)
            return crro_rsa.check_signature(public_key, plaintext)

    else:  # mean an ecc public key
        public_key = tuple(map(int, champ_clepublique.get().split()))
        if file == True:
            return crro.check_signature(public_key, plaintext.decode())
        else:
            return crro.check_signature(public_key, plaintext)

def decrypt_with_the_right_type(ciphertext, file=False):
    private_key_str = champ_clepriver.get()

    try:

        if " " in private_key_str:  # mean a rsa private key
            private_key = tuple(map(int, champ_clepriver.get().split()))
            if file == True:
                return crro_rsa.decrypt(private_key, ciphertext)
            else:
                return crro_rsa.decrypt(private_key, ciphertext).decode()

        else:  # mean an ecc private key
            private_key = int(champ_clepriver.get())
            if file == True:
                return crro.decrypt(private_key, ciphertext)
            else:
                return crro.decrypt(private_key, ciphertext).decode()
    except Exception as e:
        messagebox.showerror("Error decryption", f"{e} Decryption Failed")

def decrypteraes(file=None): # File is here str
    global type
    if type == 1 and not champ_clepriver.get():
        liste_certificat()
        return

    elif type == 2 and not champ_clepriver.get():
        liste_certificat()
        return

    elif type == 5 and not champ_clepriver.get():
        liste_certificat()
        return

    if sign == 1 and not champ_clepublique.get():
        ouvrir_deuxieme_fenetre()

    else:
        def bar_de_chargement():
            root = tk.Toplevel()
            root.title("Decryption...")

            # Obtenir les dimensions de l'écran
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()

            # Calculer les coordonnées pour centrer la fenêtre de chargement
            window_width = 300
            window_height = 100
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2

            root.geometry(f"{window_width}x{window_height}+{x}+{y}")

            root.grab_set()  # Mettre la fenêtre en premier plan

            progress_bar = ttk.Progressbar(root, orient="horizontal", length=window_width - 20, mode="indeterminate")
            progress_bar.pack(pady=20)
            progress_bar.start()

            def decrypteraes_thread():
                global type
                global sign
                root.update()
                #try:
                if file != None:
                    plaintext = file
                else:
                    plaintext = champ_message.get("1.0", tk.END).strip()

                if type == 1: #decryption is needed
                    if file != None:
                        plaintext = decrypt_with_the_right_type(plaintext.decode(), file=True)
                    else:
                        plaintext = decrypt_with_the_right_type(plaintext)

                if sign == 1: #signature is needed
                    if file != None:
                        sig_is_True, plaintext = check_sign_with_the_right_type(plaintext, file=True)
                        plaintext = base64.urlsafe_b64decode(plaintext.encode())
                    else:
                        sig_is_True, plaintext = check_sign_with_the_right_type(plaintext)

                    if sig_is_True == True:
                        cle_publique_str = champ_clepublique.get()
                        if messagebox.askyesno("Signature verified",
                                               "The author of this message is (SHA256) : " + "\n   " + sha256_hash(
                                                   cle_publique_str) + "\n   " + "\nDo you want to see the full public key?"):

                            messagebox.showinfo("Signature ",
                                                "public key :" + cle_publique_str)
                    else:
                        messagebox.showwarning("Invalid or missing signature",
                                               "You can't be sure who wrote this message.")

                if file != None:
                    return plaintext
                else:
                    champ_message.delete('1.0', tk.END)
                    champ_message.insert(tk.END, plaintext)
                    return

                #except Exception as e:
                    #root.destroy()
                    #messagebox.showerror("decryption failed", "decryption failed: " + str(e))

            if file != None:
                result_queue = queue.Queue()
                thread = threading.Thread(target=lambda q: q.put(decrypteraes_thread()), args=(result_queue,))
                thread.start()
                thread.join()  # Attendre que le thread se termine
            else:
                threading.Thread(target=decrypteraes_thread).start()

            fenetre.after(1, root.destroy)

            if file != None:
                # Récupérer le résultat de la file d'attente
                result = result_queue.get()

                print("thread", result)

            if file != None:
                return result

        data = bar_de_chargement()

    if file != None:
        return data


def export_key_pair():
    export_keys(3)


def export_key_pu():
    export_keys(2)


def export_key_pr():
    export_keys(1)


def export_keys(wich_key):
    global key_access_window

    if key_access_window is not None:
        key_access_window.deiconify()
        return

    key_access_window = tk.Toplevel(fenetre)
    key_access_window.title("Access Key Pair")

    def on_key_access_window_close():
        global key_access_window
        key_access_window.destroy()
        key_access_window = None

    key_access_window.protocol("WM_DELETE_WINDOW", on_key_access_window_close)

    label_nom = ttk.Label(key_access_window, text="Name:", font=("Helvetica", 12))
    label_nom.grid(padx=120)
    champ_nom = ttk.Entry(key_access_window, width=50)
    champ_nom.grid(padx=5)
    champ_nom.focus()

    label_password = ttk.Label(key_access_window, text="Password:", font=("Helvetica", 12))
    label_password.grid(padx=120)
    champ_password = ttk.Entry(key_access_window, width=50, show="*")
    champ_password.grid()

    def access_key_pair3(event=None):
        global chiffrage
        global export_key

        password = champ_password.get().strip()
        name = champ_nom.get().strip()
        double_hash = "Nom: " + champ_nom.get().strip()

        with open("key_pairs.txt", "r") as file:
            lines = file.readlines()
            found = False
            for i in range(0, len(lines), 5):  # Increment range by 5 since each pair occupies 5 lines
                if lines[i].strip() == double_hash:
                    encrypted_public_key = lines[i + 3].strip().split(": ")[1]
                    encrypted_private_key = lines[i + 4].strip().split(": ")[1]

                    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'salt', 100000)

                    public_key = scrro.decrypt(key, encrypted_public_key.encode('utf-8')).decode('utf-8')
                    private_key = scrro.decrypt(key, encrypted_private_key.encode('utf-8')).decode('utf-8')
                    bureau = os.path.expanduser("~/Desktop")

                    if wich_key == 3:
                        with open(os.path.join(bureau, name + "_SECRET.asc"), "wb") as file:
                            public_key = public_key.split(" ")
                            if int(public_key[0]) == 65537:
                                private_key = private_key.split(" ")

                            file.write(create_crro_block(tuple(public_key), private_key))
                            messagebox.showinfo("Success", "The key pair has been successfully export.")
                    elif wich_key == 2:
                        with open(os.path.join(bureau, name + "_PUBLIC.asc"), "wb") as file:

                            file.write(create_crro_block(tuple(public_key.split(" "))))
                            messagebox.showinfo("Success", "The public key has been successfully export.")

                    # Exporting only the private key is not accessible because finding public key from rsa private key
                    # can be difficult
                    elif wich_key == 1:
                        with open(os.path.join(bureau, name + "_PRIVATE.asc"), "w") as file:

                            file.write(f"Private Key: {private_key}\n")

                        messagebox.showinfo("Success", "The private key has been successfully export.")
                    else:
                        messagebox.showerror("Error", "Please fill in all the fields.")

                    found = True
                    refresh_sha256_and_encryption_type()
                    break

            if not found:
                messagebox.showerror("Access denied", "Incorrect password.")

        on_key_access_window_close()

    champ_password.bind("<Return>", access_key_pair3)

    bouton_access = ttk.Button(key_access_window, text="Access", command=access_key_pair3)
    bouton_access.grid(pady=3)


acces_key = 0


def acces_key_paire():
    global acces_key
    acces_key = 3
    open_key_access_window2()


def access_key_pu():
    global acces_key
    acces_key = 2
    open_key_access_window2()


def acces_key_pr():
    global acces_key
    acces_key = 1
    open_key_access_window2()


def open_key_access_window2():
    global key_access_window

    if key_access_window is not None:
        key_access_window.deiconify()
        return

    key_access_window = tk.Toplevel(fenetre)
    key_access_window.title("Access to the key pair")

    def on_key_access_window_close():
        global key_access_window
        key_access_window.destroy()
        key_access_window = None

    key_access_window.protocol("WM_DELETE_WINDOW", on_key_access_window_close)

    label_nom = ttk.Label(key_access_window, text="Name:", font=("Helvetica", 12))
    label_nom.grid(padx=120)
    champ_nom = ttk.Entry(key_access_window, width=50)
    champ_nom.grid(pady=3, padx=5)

    label_password = ttk.Label(key_access_window, text="Password:", font=("Helvetica", 12))
    label_password.grid(padx=120)
    champ_password = ttk.Entry(key_access_window, width=50, show="*")
    champ_password.grid(pady=3)

    def access_key_pair3(event=None):
        global chiffrage
        global acces_key
        password = champ_password.get().strip()

        # Hachage du mot de passe avec SHA-256
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        # Double hachage du hash du mot de passe avec SHA-256
        double_hash = "Nom: " + champ_nom.get().strip()

        # Lecture du fichier texte pour trouver la paire de clés chiffrées correspondante
        with open("key_pairs.txt", "r") as file:
            lines = file.readlines()
            found = False
            for i in range(0, len(lines), 5):  # Increment range by 5 since each pair occupies 5 lines
                if lines[i].strip() == double_hash:
                    encrypted_public_key = lines[i + 3].strip().split(": ")[1]
                    encrypted_private_key = lines[i + 4].strip().split(": ")[1]

                    # Déchiffrement des clés avec le mot de passe
                    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'salt', 100000)
                    encoded_key = base64.urlsafe_b64encode(key)
                    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'salt', 100000)

                    public_key = scrro.decrypt(key, encrypted_public_key.encode('utf-8')).decode('utf-8')
                    private_key = scrro.decrypt(key, encrypted_private_key.encode('utf-8')).decode('utf-8')

                    if acces_key == 3:
                        champ_clepriver.delete(0, tk.END)
                        champ_clepriver.insert(tk.END, private_key)
                        champ_clepublique.delete(0, tk.END)
                        champ_clepublique.insert(tk.END, public_key)
                    elif acces_key == 2:
                        champ_clepublique.delete(0, tk.END)
                        champ_clepublique.insert(tk.END, public_key)
                    elif acces_key == 1:
                        champ_clepriver.delete(0, tk.END)
                        champ_clepriver.insert(tk.END, private_key)

                    line = champ_nom.get().strip()

                    found = True
                    refresh_sha256_and_encryption_type()
                    break

            if not found:
                messagebox.showerror("Access denied", "Invalid password.")

        on_key_access_window_close()

    # Associer la touche "Entrée" à la fonction access_key_pair3
    champ_password.bind("<Return>", access_key_pair3)

    # Ajouter le bouton "Accéder" s'il n'est pas déjà présent dans la fenêtre
    bouton_access = ttk.Button(key_access_window, text="Access", command=access_key_pair3)
    bouton_access.grid(pady=3)


def open_key_access_window3(line, close_or_not):
    global key_access_window
    global chiffrage
    if key_access_window is not None:
        key_access_window.deiconify()
        return

    key_access_window = tk.Toplevel(fenetre)
    key_access_window.title("Access to the key pair")

    def on_key_access_window_close():
        global key_access_window
        key_access_window.destroy()
        key_access_window = None

    key_access_window.protocol("WM_DELETE_WINDOW", on_key_access_window_close)

    label_nom = ttk.Label(key_access_window, text="Name:", font=("Helvetica", 12))
    label_nom.grid(padx=120, pady=3)
    champ_nom = ttk.Entry(key_access_window, width=50)
    champ_nom.grid(padx=5)

    champ_nom.delete(0, tk.END)
    champ_nom.insert(tk.END, line.strip())

    label_password = ttk.Label(key_access_window, text="Password:", font=("Helvetica", 12))
    label_password.grid(padx=120, pady=3)
    champ_password = ttk.Entry(key_access_window, width=50, show="*")
    champ_password.grid()
    champ_password.focus_set()

    def access_key_pair3(event=None):
        global chiffrage

        password = champ_password.get().strip()

        # Hachage du mot de passe avec SHA-256
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        # Double hachage du hash du mot de passe avec SHA-256
        double_hash = "Nom: " + champ_nom.get().strip()

        # Lecture du fichier texte pour trouver la paire de clés chiffrées correspondante
        with open("key_pairs.txt", "r") as file:
            lines = file.readlines()
            found = False
            for i in range(0, len(lines), 5):  # Increment range by 5 since each pair occupies 5 lines
                if lines[i].strip() == double_hash:
                    encrypted_public_key = lines[i + 3].strip().split(": ")[1]
                    encrypted_private_key = lines[i + 4].strip().split(": ")[1]

                    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'salt', 100000)

                    private_key = scrro.decrypt(key, encrypted_private_key.encode('utf-8')).decode('utf-8')

                    champ_clepriver.delete(0, tk.END)

                    champ_clepriver.insert(tk.END, private_key)

                    found = True
                    refresh_sha256_and_encryption_type()
                    break

            if not found:
                messagebox.showerror("Access denied", "Invalid password.")

        if close_or_not == 1:

            on_key_access_window_close()
            messagebox.showinfo("Access authorized", "Access to the key pair authorized.")

        else:
            global key_access_window
            key_access_window.destroy()
            key_access_window = None

    champ_password.bind("<Return>", access_key_pair3)
    bouton_access = ttk.Button(key_access_window, text="access", command=access_key_pair3)
    bouton_access.grid(pady=3)


def ouvrir_site():
    # Afficher une boîte de dialogue demandant à l'utilisateur s'il veut accéder au site
    response = messagebox.askyesno("Confirmation", "Do you want to go to the website ?")

    if response:
        # Ouvrir le site dans un navigateur
        import webbrowser
        webbrowser.open("http://crro.neocities.org")


def ouvrir_github():
    # Afficher une boîte de dialogue demandant à l'utilisateur s'il veut accéder au site
    response = messagebox.askyesno("Confirmation", "Do you want to go to Github ?")

    if response:
        # Ouvrir le site dans un navigateur
        import webbrowser
        webbrowser.open("https://github.com/Elg256/CRRO")


def ouvrir_documentation():
    # Ouvrir le fichier "documentation.pdf" dans le lecteur de PDF par défaut
    try:
        import webbrowser
        webbrowser.open("documentation.pdf")
    except Exception as e:
        messagebox.showerror("Error", "Failed to open documentation : {}".format(e))


def ouvrir_version():
    version = tk.Toplevel(fenetre)
    version.title("About")

    # Vérifier si le fichier d'image existe
    image_path = "img/logo.png"
    if os.path.exists(image_path):
        try:
            # Créer un objet PhotoImage pour l'image
            logo_image = tk.PhotoImage(file=image_path)

            # Redimensionner l'image (par exemple, diviser par 2 pour la réduire de moitié)
            resized_image = logo_image.subsample(5, 5)

            # Créer un label pour afficher l'image redimensionnée
            label_image = tk.Label(version, image=resized_image)
            label_image.pack(pady=5, padx=5)

            # Il est important de garder une référence à l'objet PhotoImage pour éviter que l'image ne soit supprimée par le garbage collector
            label_image.image = resized_image
        except tk.TclError as e:
            # En cas d'erreur, afficher un message d'erreur
            print("Error loading image :", e)
    else:
        print("Image file not found :", image_path)

    label_version = tk.Label(version, text="Versions:", font=("Helvetica", 12))
    label_version.pack(pady=5, padx=5)
    label_version = tk.Label(version, text="Application : CRRO 2.9.6 ", font=("Helvetica", 12))
    label_version.pack(pady=2, padx=5)
    label_version = tk.Label(version, text="Encryption: CryptCrro 0.1.4", font=("Helvetica", 12))
    label_version.pack(pady=2, padx=5)
    label_version = tk.Label(version, text="Release date : 27/02/2025", font=("Helvetica", 12))
    label_version.pack(pady=5, padx=10)


def refresh_sha256_and_encryption_type(event=None):
    global type

    cle_publique = champ_clepublique.get()

    if champ_clepublique.get().strip() != None:

        hash_cle_publique = sha256_hash(cle_publique)
        sha256.set(hash_cle_publique)

    if cle_publique == "":
        sha256.set("None")

    if type == 4:
        return


def paracle_visible2():
    global cle_visible
    global viscle2
    global cle_visible2
    if champ_clepriver.winfo_ismapped():
        champ_clepriver.grid_forget()
        label_clepriver.grid_forget()
        cle_visible2 = 2

    else:
        label_clepriver.grid(row=0, column=5)
        champ_clepriver.grid(row=1, column=5, padx=10)  # Affiche le champ de texte
        cle_visible2 = 1
    fenetre.update_idletasks()

def toggle_checkbox():
    global sign
    global sign2
    if checkbox_var.get() == 1:

        sign = 1
        sign2.set("Enable")
        label_typechiffrage2.config(text=sign2.get())
    else:
        sign = 2
        sign2.set("Disable")
        label_typechiffrage2.config(text=sign2.get())

    print("sign is",sign)


def toggle_checkbox1():
    global sign
    global sign2
    global type
    global chiffrage
    global type2
    if checkbox_var1.get() == 1:

        type = 1
        chiffrage = 2
        type2.set("Enable")
        label_typechiffrage2.config(text=type2.get())

    else:

        type = 4
        chiffrage = 2
        type2.set("Disable")
        label_typechiffrage2.config(text=type2.get())

    refresh_sha256_and_encryption_type()

    print("type is", type)


def refresh_check_box():
    global sign
    global type

    if sign == 1:
        checkbox.state(["selected"])
    elif sign == 2:
        checkbox.state(["!selected"])

    if type == 4:
        checkbox1.state(["!selected"])
    elif type == 5:
        checkbox1.state(["selected"])
    elif type == 1:
        checkbox1.state(["selected"])


fenetre = tk.Tk()

fenetre.title("CRRO")

w, h = (fenetre.winfo_screenwidth(), fenetre.winfo_screenheight(),)

if os.name == "nt":
    fenetre.state('zoomed')
elif os.name == "posix":
    fenetre.geometry("%dx%d" % (w, h))

if os.name == "nt":
    fenetre.iconbitmap("./img/crro_logo.ico")
elif os.name == "posix":
    pass

fenetre.minsize(400, 400)

charger_parametres()
type2 = tk.StringVar()
sign2 = tk.StringVar()


def setaffiche():
    if chiffrage == 2:
        if type == 1:
            type2.set("Enable")
        elif type == 3:
            type2.set("AES")
        elif type == 4:
            type2.set("Disable")

def setaffiche2():
    if sign == 2:
        sign2.set("Disable")
    if sign == 1:
        sign2.set("Enable")


def toggle_key_visibility2():
    global cle_visible2

    if cle_visible2 == 2:
        champ_clepriver.grid_forget()
        label_clepriver.grid_forget()

setaffiche()
setaffiche2()



menubar = tk.Menu(fenetre)
fenetre.config(menu=menubar)


def fermer_fenetre():
    enregistrer_parametres()


def on_fenetre_close():
    # Appeler la fonction pour enregistrer les paramètres
    enregistrer_parametres()


# Définir le comportement lors de la fermeture de la fenêtre principale
fenetre.protocol("WM_DELETE_WINDOW", on_fenetre_close)

private_key_image = PhotoImage(file="img/private_key_menu.png")

lock_image = PhotoImage(file="img/lock_menu.png")
lock_open_image = PhotoImage(file="img/lock_open_menu.png")
smartcard_image = PhotoImage(file="img/smartcard_menu.png")
exit_image = PhotoImage(file="img/exit.png")
copy_image = PhotoImage(file="img/copy.png")
import_image = PhotoImage(file="img/import_key.png")
export_image = PhotoImage(file="img/export_key.png")
image_file_decrypt = PhotoImage(file="img/file_decrypt.png")
register_image = PhotoImage(file="img/registre.png")
sign_image = PhotoImage(file="img/sign.png")
show_image = PhotoImage(file="img/eyes.png")
block_lenght_image = PhotoImage(file="img/block_lenght.png")
encryption_type_image = PhotoImage(file="img/puzzle.png")

# Création du menu "Fichier"
file_menu = tk.Menu(menubar, tearoff=False)
menubar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="New Key Pair", command=open_key_management_window, image=private_key_image, compound=LEFT)
file_menu.add_command(label="Import Key", command=import_key_pair, image=import_image, compound=LEFT)
file_menu.add_separator()

menu_access = Menu(file_menu, tearoff=0)
menu_access.add_command(label="Access Public Keys", command=access_key_pu)
menu_access.add_command(label="Access Private Keys", command=acces_key_pr)
menu_access.add_command(label="Access Key Pairs", command=acces_key_paire)
file_menu.add_cascade(label="Access Keys", underline=0, menu=menu_access, image=private_key_image, compound=LEFT)

menu_recent = Menu(file_menu, tearoff=0)
menu_recent.add_command(label="Export Public Key", command=export_key_pu)
menu_recent.add_command(label="Export Private Key", command=export_key_pr)
menu_recent.add_command(label="Export Key Pair", command=export_key_pair)
file_menu.add_cascade(label="Export Keys", underline=0, menu=menu_recent, image=export_image, compound=LEFT)

file_menu.add_command(label="Encrypt/Decrypt Files", command=ouvrir_file, image=image_file_decrypt, compound=LEFT)
file_menu.add_command(label="Copy Notepad", command=copy_result, image=copy_image, compound=LEFT)

file_menu.add_separator()
file_menu.add_command(label="Exit", command=fermer_fenetre, image=exit_image, compound=LEFT)

# Create the "Encryption" menu
encrypt_menu = tk.Menu(menubar, tearoff=False)
menubar.add_cascade(label="Encryption", menu=encrypt_menu)
encrypt_menu.add_command(label="Encrypt Notepad", command=lambda: crypteraes(file=None), image=lock_image,
                         compound=LEFT)
encrypt_menu.add_command(label="Decrypt Notepad", command=lambda: decrypteraes(), image=lock_open_image, compound=LEFT)
encrypt_menu.add_command(label="Encrypt/Decrypt Files", command=ouvrir_file, image=image_file_decrypt, compound=LEFT)
#encrypt_menu.add_command(label="Encryption Type", command=ouvrir_type_chiffrage, image=encryption_type_image,
                         #compound=LEFT)

key_menu = tk.Menu(menubar, tearoff=False)
menubar.add_cascade(label="Key Management", menu=key_menu)
key_menu.add_command(label="New Key Pair", command=open_key_management_window, image=private_key_image, compound=LEFT)
key_menu.add_command(label="Import Key", command=import_key_pair, image=import_image, compound=LEFT)
key_menu.add_command(label="Register Public Key", command=ouvrir_deuxieme_fenetre, image=register_image, compound=LEFT)

menu_access = Menu(key_menu, tearoff=0)
menu_access.add_command(label="Access Public Keys", command=access_key_pu)
menu_access.add_command(label="Access Private Keys", command=acces_key_pr)
menu_access.add_command(label="Access Key Pairs", command=acces_key_paire)
key_menu.add_cascade(label="Access Keys", underline=0, menu=menu_access, image=private_key_image, compound=LEFT)

menu_recent = Menu(key_menu, tearoff=0)
menu_recent.add_command(label="Export Public Key", command=export_key_pu)
menu_recent.add_command(label="Export Private Key", command=export_key_pr)
menu_recent.add_command(label="Export Key Pair", command=export_key_pair)

key_menu.add_cascade(label="Export Keys", underline=0, menu=menu_recent, image=export_image, compound=LEFT)
# I put the Refresh all certificats after the function for it because I don't know how to code clean, sorry :)

smartcard_menu = tk.Menu(menubar, tearoff=False)
menubar.add_cascade(label="Smartcard", menu=smartcard_menu)
smartcard_menu.add_command(label="Use Smartcard", command=use_smartcard, image=smartcard_image, compound=LEFT)
smartcard_menu.add_command(label="Create Smartcard", command=create_smartcard, image=smartcard_image, compound=LEFT)

parameters_menu = tk.Menu(menubar, tearoff=False)
menubar.add_cascade(label="Parameters", menu=parameters_menu)
parameters_menu.add_command(label="Show/Hide Private Key", command=paracle_visible2, image=show_image, compound=LEFT)
#parameters_menu.add_command(label="Toggle Signature", command=type_signature, image=sign_image, compound=LEFT)
#parameters_menu.add_command(label="Encryption Type", command=ouvrir_type_chiffrage, image=encryption_type_image,
                            #compound=LEFT)

real_money_image = PhotoImage(file="img/real_money.png")
logo_elg256 = PhotoImage(file="img/logo_elg256.png")
logo_crro = PhotoImage(file="img/logo_crro.png")

about_menu = tk.Menu(menubar, tearoff=False)
menubar.add_cascade(label="About", menu=about_menu)
about_menu.add_command(label="Version: 2.9.6", command=ouvrir_version)
about_menu.add_command(label="Our Website: crro.neocities.org", command=ouvrir_site, image=logo_crro, compound=LEFT)
about_menu.add_command(label="Our Github: github.com/Elg256/CRRO", command=ouvrir_github, image=logo_elg256,
                       compound=LEFT)
about_menu.add_command(label="Documentation", command=ouvrir_documentation, image=copy_image, compound=LEFT)
about_menu.add_command(label="Support Us", command=adressebtc, image=real_money_image, compound=LEFT)

frame = tk.Frame(fenetre)
frame.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

frame.columnconfigure(3, weight=2)
frame.rowconfigure(3, weight=2)

image_lock = PhotoImage(file="img/lock.png")

bouton_crypter = ttk.Button(frame, text="Encrypt", image=image_lock, compound=LEFT, width=10,
                            command=lambda: crypteraes(file=None))
bouton_crypter.grid(row=0, column=0, padx=2.5, ipady=12)

image_lock_open = PhotoImage(file="img/lock_open.png")

bouton_crypter = ttk.Button(frame, text="Decrypt", image=image_lock_open, compound=LEFT, width=10,
                            command=lambda: decrypteraes())
bouton_crypter.grid(row=0, column=1, padx=10, sticky="ne", ipady=12)

label_typechiffrage = ttk.Label(frame, text="Encryption:", font=("Helvetica", 8))
label_typechiffrage.grid(row=1, column=0, padx=1)
label_typechiffrage2 = ttk.Label(frame, textvariable=type2)
label_typechiffrage2.grid(row=2, column=0, padx=1)

label_signature = ttk.Label(frame, text="Signature:", font=("Helvetica", 8))
label_signature.grid(row=1, column=1, padx=1)
label_signature2 = ttk.Label(frame, textvariable=sign2)
label_signature2.grid(row=2, column=1, padx=1)

label_clepublique = ttk.Label(frame, text="Public Key:", font=("Helvetica", 12))
label_clepublique.grid(row=0, column=3, padx=10)
champ_clepublique = ttk.Entry(frame, width=68)
champ_clepublique.grid(row=1, column=3, padx=10)
champ_clepublique.bind('<KeyRelease>', refresh_sha256_and_encryption_type)

label_sign2 = ttk.Label(frame, text="SHA256:")
label_sign2.grid(row=2, column=3, padx=0)
# Create the variable StringVar to store the result SHA-256 (sign2)
sha256 = tk.StringVar()
label_sign2_result = ttk.Label(frame, textvariable=sha256)
label_sign2_result.grid(row=3, column=3, padx=0)
sha256.set("None")


def copy():
    content = champ_message.get("sel.first", "sel.last")
    fenetre.clipboard_clear()
    fenetre.clipboard_append(content)


def cut():
    content = champ_message.get("sel.first", "sel.last")
    fenetre.clipboard_clear()
    fenetre.clipboard_append(content)
    champ_message.delete("sel.first", "sel.last")


def paste():
    content = fenetre.clipboard_get()
    champ_message.insert("insert", content)


def undo():
    champ_message.edit_undo()


def undo_bouton():
    champ_message.edit_undo()


popup_menu = tk.Menu(fenetre, tearoff=0)
popup_menu.add_command(label="Copy", command=copy)
popup_menu.add_command(label="Cut", command=cut)
popup_menu.add_command(label="Paste", command=paste)
popup_menu.add_separator()
popup_menu.add_command(label="Undo", command=undo)


def copier_cle1(line, certificats_fenetre):
    certificats_fenetre.destroy()
    open_key_access_window3(line, close_or_not=1)


def copier_cle2(line):
    open_key_access_window3(line, close_or_not=1)


def liste_certificat():
    global certificats_fenetre
    if certificats_fenetre is not None and certificats_fenetre.winfo_exists():
        certificats_fenetre.deiconify()
        return
    certificats_fenetre = tk.Toplevel(fenetre)

    certificats_fenetre.title("Certificate Management")

    frame_ajout = tk.Frame(certificats_fenetre)
    frame_ajout.grid(pady=10)

    frame_cle = tk.Frame(certificats_fenetre, pady=5)
    frame_cle.grid(column=1, padx=10, pady=2)

    nom = tk.Label(certificats_fenetre, text="Name:")
    nom.grid(row=0, column=0, padx=10, sticky="W")

    type = tk.Label(certificats_fenetre, text="Type:")
    type.grid(row=0, column=0)

    with open("key_pairs.txt", "r") as fichier:
        contenu = fichier.readlines()
        i = 0  # Utilisé pour suivre la position actuelle dans le contenu
        for ligne in contenu:
            if ligne.startswith("Nom:"):
                nom = ligne.split(": ")[1].strip()
                typecleaff = contenu[i + 1].split(": ")[1].strip()  # Ligne suivante

                frame_cle = tk.Frame(certificats_fenetre)
                frame_cle.grid(column=0, padx=10, pady=2)

                # Créer la variable Tkinter StringVar pour stocker la valeur du nom
                nom_var = tk.StringVar()
                nom_var.set(nom)

                typecleaff_var = tk.StringVar()
                typecleaff_var.set(typecleaff)
                entry_nom_priv = tk.Entry(frame_cle, textvariable=nom_var, width=20,
                                          highlightbackground="gray", highlightcolor="gray", highlightthickness=1)
                entry_nom_priv.grid(row=0, column=0, padx=0, pady=0, sticky="w")

                entry_type = tk.Entry(frame_cle, textvariable=typecleaff_var, width=20
                                      , highlightbackground="gray", highlightcolor="gray", highlightthickness=1)
                entry_type.grid(row=0, column=1, padx=0, pady=0, sticky="w")

                def copier_cle_callback(nom=nom):  # Utiliser l'argument par défaut
                    copier_cle1(nom, certificats_fenetre)  # Remplacer "" par la clé publique que vous voulez utiliser

                button_copier = ttk.Button(frame_cle, text="Use", command=copier_cle_callback)
                button_copier.grid(row=0, column=2, padx=5, pady=5, sticky="w")

                def supprimer_callback(frame=frame_cle, key=""):
                    confirmer_suppression(frame, key, nom)

                button_supprimer = ttk.Button(frame_cle, text="Delete", command=supprimer_callback)
                button_supprimer.grid(row=0, column=3, padx=5, pady=5, sticky="w")

                # Passer à la ligne suivante après avoir traité le nom
                i += 1
            else:
                # Passer à la ligne suivante si la ligne ne commence pas par "Nom:"
                i += 1


certificats_fenetre = None


def update_scrollbar_visibility(event=None):
    num_visible_lines = champ_message.cget("height")
    num_total_lines = int(champ_message.index("end-1c").split('.')[0])
    if num_total_lines > num_visible_lines:
        scrollbar.pack(side="right", fill="y")
    else:
        scrollbar.pack_forget()


label_message = ttk.Label(frame, text="Notepad:", font=("Helvetica", 10))
label_message.grid(row=4, column=0)
champ_message = Text(fenetre, undo=True)
champ_message.config(bd=1, relief="solid", highlightbackground="light blue",
                     undo=True, highlightcolor="light blue")

scrollbar = ttk.Scrollbar(champ_message)
scrollbar.pack(side="right", fill="y")

scrollbar.config(command=champ_message.yview)

champ_message.config(yscrollcommand=scrollbar.set)

scrollbar.pack_forget()

champ_message.bind("<Key>", update_scrollbar_visibility)

# Configurer la deuxième ligne pour s'étirer en hauteur
fenetre.grid_rowconfigure(2, weight=1)

# Configurer la première colonne pour s'étirer en largeur
fenetre.grid_columnconfigure(0, weight=1)

espace_vide = ttk.Label(fenetre)
espace_vide.grid(row=6)

bouton_retour = ttk.Button(frame, text="Undo", command=undo_bouton, width=1)
bouton_retour.grid(row=4, column=1, padx=15)

label_destinataire = ttk.Label(frame, text="Management:", font=("Helvetica", 10))
label_destinataire.grid(row=4, column=0, pady=10, sticky="W", padx=5)

# frame3
frame3 = tk.Frame(fenetre, borderwidth=2, relief="solid")
frame3.grid(row=2, column=0, sticky="NEW")  # Utiliser 'NSEW' pour que le cadre s'étende dans toutes les directions

frame_chiffrer = tk.Frame(frame3)  # Créez un cadre pour regrouper le label et le bouton
frame_chiffrer.grid(sticky="W")

label_ch = tk.Label(frame3, text="Encrypt:", font=("Helvetica", 10))
label_ch.grid(row=0, column=0, pady=10, padx=5)

label_dech = tk.Label(frame3, text="Signature:", font=("Helvetica", 10))
label_dech.grid(row=1, column=0, pady=10, padx=5)

checkbox_var1 = tk.IntVar()
# Création de la case à cocher
checkbox1 = ttk.Checkbutton(frame3, variable=checkbox_var1, command=toggle_checkbox1)
checkbox1.grid(row=0, column=1, pady=10, padx=5)

if type != 4:
    checkbox_var1.set(1)

bouton_registre = tk.Label(frame3, text="Public key ", font=("Helvetica", 12))
bouton_registre.grid(sticky="W", row=5, column=2)  # Utilisez pack pour le bouton à droite

frame_chiffrer.grid(row=5, column=2, columnspan=2)

label_sign3 = tk.Label(frame3, text="SHA256:")
label_sign3.grid(row=6, padx=0, column=3)
# Créer la variable StringVar pour stocker le résultat SHA-256 (sign2)
sha2562 = tk.StringVar()
label_sign3_result = tk.Label(frame3, textvariable=sha256)
label_sign3_result.grid(row=7, padx=1, column=3)
sha2562.set("None")

ligneespace = tk.Label(frame3, text="  ")
ligneespace.grid(row=8, padx=0)

frame_signer = tk.Frame(frame3)  # Créez un cadre pour regrouper le label et le bouton
frame_signer.grid(sticky="W")

checkbox_var = tk.IntVar()
# Création de la case à cocher
checkbox = ttk.Checkbutton(frame3, variable=checkbox_var, command=toggle_checkbox)
checkbox.grid(row=1, column=1, pady=10, padx=5)

if sign == 1:
    checkbox_var.set(1)

bouton_signerpour = tk.Label(frame3, text="Private key ", font=("Helvetica", 12))

bouton_signerpour.grid(sticky="W", row=9, column=2)
frame_cle_priver = tk.Frame(frame3)
frame_cle_priver.grid(row=9, column=4, padx=5)

label_clepriver = tk.Label(frame_cle_priver, text="Private key:", font=("Helvetica", 12))
label_clepriver.grid(row=8, column=4)

champ_clepriver = tk.Entry(frame_cle_priver, width=60)
champ_clepriver.grid(sticky="W", row=9, column=4)
champ_clepriver.config(highlightbackground="gray", highlightcolor="gray", highlightthickness=1)

frame3.grid_forget()

# frame4

frame4 = tk.Frame(fenetre, borderwidth=2, relief="solid")
frame4.grid(row=2, column=0, sticky="NSEW")

file = open("key_pairs.txt", "a+")


def show_private_key_certificat():

    for widget in frame4.winfo_children():
        widget.destroy()

    nom = ttk.Label(frame4, text="Name:")
    nom.grid(row=0, column=1, padx=10, pady=5)

    typecle = ttk.Label(frame4, text="Type:")
    typecle.grid(row=0, column=2, pady=5)

    iden = ttk.Label(frame4, text="identifier (SHA256):")
    iden.grid(row=0, column=3, pady=5)


    with open("key_pairs.txt", "r") as fichier:
        contenu = fichier.readlines()
        if not contenu:
            start_message = ttk.Label(frame4, text="To create a new key pair go to \"File\" then \"New Key Pair\".")
            start_message.grid(row=1, column=2, pady=5)

        i = 0  # Utilisé pour suivre la position actuelle dans le contenu
        entry_noms = []
        for ligne in contenu:
            if ligne.startswith("Nom:"):
                nom = ligne.split(": ")[1].strip()
                entry_noms.append(nom)
                typecleaff = contenu[i + 1].split(": ")[1].strip()  # Ligne suivante
                hashcle = contenu[i + 2].split(": ")[1].strip()

                frame_nom = tk.Frame(frame4, pady=0)
                frame_nom.grid(row=i + 1, column=1)

                frame_typ = tk.Frame(frame4, pady=0)
                frame_typ.grid(row=i + 1, column=2)

                frame_id = tk.Frame(frame4, pady=0)
                frame_id.grid(row=i + 1, column=3)

                frame_bou = tk.Frame(frame4, pady=0)
                frame_bou.grid(row=i + 1, column=7)

                # Créer la variable Tkinter StringVar pour stocker la valeur du nom
                nom_var = tk.StringVar()
                nom_var.set(nom)

                typecleaff_var = tk.StringVar()
                typecleaff_var.set(typecleaff)

                hashcle_var = tk.StringVar()
                hashcle_var.set(hashcle)

                label_vide = tk.Label(frame_nom, text=" ")
                label_vide.grid(row=i + 1, column=1, padx=3, pady=0, sticky="w")

                entry_nom = tk.Entry(frame_nom, textvariable=nom_var, width=20, highlightbackground="gray",
                                     highlightcolor="gray", highlightthickness=1)
                entry_nom.grid(row=i + 1, column=2, padx=0, pady=0, sticky="w")

                entry_type = tk.Entry(frame_typ, textvariable=typecleaff_var, width=20, highlightbackground="gray",
                                      highlightcolor="gray", highlightthickness=1)
                entry_type.grid(row=i + 1, column=3, padx=0, pady=0, sticky="w")

                entry_id = tk.Entry(frame_id, textvariable=hashcle_var, width=70,
                                    highlightbackground="gray", highlightcolor="gray", highlightthickness=1)
                entry_id.grid(row=i + 1, column=4, padx=0, pady=0, sticky="w")

                def copier_cle_callback(nom=nom):  # Utiliser l'argument par défaut
                    copier_cle2(nom)

                button_copier = ttk.Button(frame_bou, text="Use", command=copier_cle_callback)
                button_copier.grid(row=i + 1, column=4, padx=5, pady=5, sticky="w")

                def supprimer_callback(nom, frame):
                    response = messagebox.askyesno("Confirmation", "Are you sure you want to delete the private key?")
                    if response:
                        with open("key_pairs.txt", "r") as fichier:
                            lignes = fichier.readlines()

                        with open("key_pairs.txt", "w") as fichier:
                            i = 0
                            while i < len(lignes):
                                ligne = lignes[i]
                                if ligne.startswith("Nom:") and ligne.split(": ")[1].strip() == nom:
                                    # Ignorer les trois lignes du certificat actuel
                                    i += 5
                                else:
                                    fichier.write(ligne)
                                    i += 1

                        # Mettre à jour l'affichage en supprimant les widgets correspondants
                        frame.grid_forget()

                def supprimer_callback_wrapper(nom, frame):
                    return lambda: supprimer_callback(nom, frame)

                button_supprimer = ttk.Button(frame_bou, text="Delete",
                                              command=supprimer_callback_wrapper(nom, frame_bou))
                button_supprimer.grid(row=i + 1, column=5, padx=5, pady=5, sticky="w")

                # Passer à la ligne suivante après avoir traité le nom
                i += 1
            else:
                # Passer à la ligne suivante si la ligne ne commence pas par "Nom:"
                i += 1
    return entry_noms


entry_noms = show_private_key_certificat()


def refresh_all_certificates():
    show_private_key_certificat()
    update_combobox()

key_menu.add_command(label="Refresh all Certificates", command=lambda: show_private_key_certificat(),
                     image=register_image, compound=LEFT)


def on_name_selected_menu1(event):
    refresh_sha256_and_encryption_type()
    selected_name = combobox.get()

    line = selected_name
    open_key_access_window3(line, close_or_not=1)


combobox = ttk.Combobox(frame3, values=entry_noms, width=60)
combobox.grid(sticky="W", row=9, column=3, padx=10, pady=10)
combobox.bind("<<ComboboxSelected>>", on_name_selected_menu1)



with open("registre.txt", "r") as fichier:
    contenu = fichier.readlines()
    i = 0  # Utilisé pour suivre la position actuelle dans le contenu
    entry_noms_pu = []
    while i < len(contenu):
        if contenu[i].startswith("Nom:"):
            nom = contenu[i].split(": ")[1].strip()  # Obtenir le nom correctement
            entry_noms_pu.append(nom)

            if i + 1 < len(contenu) and contenu[i + 1].startswith("Cle publique:"):
                publique = contenu[i + 1].split(": ")[1].strip()  # Obtenir la clé publique correctement


                def copier_cle_callback(key=publique, nom=nom):  # Utiliser les arguments par défaut
                    copier_cle(key, nom)


                # Passer à la ligne suivante après avoir traité le nom et la clé
                i += 2
            else:
                # Si la clé publique n'est pas trouvée, passer à la ligne suivante
                i += 1
        else:
            # Passer à la ligne suivante si la ligne ne commence pas par "Nom:"
            i += 1


def recherche_clepublique(event):
    with open("registre.txt", "r") as fichier:
        contenu = fichier.readlines()
        i = 0  # Utilisé pour suivre la position actuelle dans le contenu
        selected_name = combobox2.get()
        entry_noms_pu = []
        for ligne in contenu:
            if ligne.startswith("Nom: " + selected_name):
                nom = ligne.split(": ")[1].strip()
                entry_noms_pu.append(nom)
                key = contenu[i + 1].split(": ")[1].strip()  # Ligne suivante

                copier_cle_cocobox(key, nom)

                # Passer à la ligne suivante après avoir traité le nom
                i += 1
            else:
                # Passer à la ligne suivante si la ligne ne commence pas par "Nom:"
                i += 1


def on_name_selected_menu2(event):
    selected_name = combobox2.get()
    copier_cle_callback()


combobox2 = ttk.Combobox(frame3, values=entry_noms_pu, width=60)
combobox2.grid(sticky="W", row=5, column=3, padx=10, pady=10)
combobox2.bind("<<ComboboxSelected>>", recherche_clepublique)


def update_combobox_private_key():
    with open("key_pairs.txt", "r") as fichier:
        contenu = fichier.readlines()
        entry_names = []
        for line in contenu:
            if line.startswith("Nom:"):
                name = line.split(": ")[1].strip()
                entry_names.append(name)
    combobox.config(values=entry_names)


def update_combobox_public_key():
    with open("registre.txt", "r") as fichier:
        contenu = fichier.readlines()
        entry_names_pu = []
        for line in contenu:
            if line.startswith("Nom:"):
                name = line.split(": ")[1].strip()
                entry_names_pu.append(name)
    combobox2.config(values=entry_names_pu)


def update_combobox():
    update_combobox_private_key()
    update_combobox_public_key()


lighter_blue_hex = "#cee6ed"

label_destinataire4 = ttk.Label(frame, text="Certificates:", font=("Helvetica", 12))
label_destinataire4.grid(row=4, column=0, pady=10, sticky="W", padx=5)

label_destinataire4.grid_forget()
frame4.grid_forget()

frame2 = tk.Frame(fenetre)
frame2.grid(row=0, column=0, padx=10, pady=30, sticky="N")


class ButtonApp:
    def __init__(self, frame):

        from tkinter import ttk

        style = ttk.Style()

        style.configure('3boutton.TButton')

        self.image1 = PhotoImage(file='img/button_image1.png')
        self.image2 = PhotoImage(file='img/configuration.png')
        self.image3 = PhotoImage(file='img/private_key.png')

        self.button1 = ttk.Button(frame, image=self.image1, compound=LEFT, text="Notepad", width=10,
                                  command=self.toggle_button1)
        self.button1.grid(row=0, column=7, padx=1, sticky="S", ipady=11)
        self.button1.image = self.image1  # Gardez une référence à l'image
        self.button1.bind("<Enter>", lambda event, b=self.button1: b.config())
        self.button1.bind("<Leave>", lambda event, b=self.button1: self.on_leave(event, b))

        self.button2 = ttk.Button(frame, text="Configuration", image=self.image2, compound=LEFT, width=13,
                                  command=self.toggle_button2)
        self.button2.grid(row=0, column=8, sticky="S", ipady=11)
        self.button2.bind("<Enter>", lambda event, b=self.button2: b.config())
        self.button2.bind("<Leave>", lambda event, b=self.button2: self.on_leave(event, b))

        self.button3 = ttk.Button(frame, text="Private Keys", image=self.image3, compound=LEFT, width=12,
                                  command=self.toggle_button3)
        self.button3.grid(row=0, column=9, padx=1, sticky="S", ipady=11)
        self.button3.bind("<Enter>", lambda event, b=self.button3: b.config())
        self.button3.bind("<Leave>", lambda event, b=self.button3: self.on_leave(event, b))

        self.active_button = None
        self.toggle_button1()

    def toggle_button1(self):
        self.toggle_button(self.button1)
        frame3.grid_forget()
        label_destinataire.grid_forget()

        frame3.place_forget()
        frame4.grid_forget()
        frame4.place_forget()
        label_destinataire4.grid_forget()

        label_message.grid(row=4, column=0)
        champ_message.grid(row=2, column=0, sticky="news", padx=10)
        bouton_retour.grid(row=4, column=1, padx=15, sticky="news")

    def toggle_button2(self):
        label_message.grid_forget()
        champ_message.grid_forget()
        bouton_retour.grid_forget()
        frame4.grid_forget()
        frame4.place_forget()
        label_destinataire4.grid_forget()

        marge_horizontal = 20
        frame3.grid(row=2, column=0, sticky="NEWS", padx=marge_horizontal, pady=marge_horizontal)

        label_destinataire.grid(row=4, column=0)

        self.toggle_button(self.button2)

    def toggle_button3(self):
        label_message.grid_forget()
        champ_message.grid_forget()
        bouton_retour.grid_forget()
        frame3.grid_forget()
        label_destinataire.grid_forget()
        frame3.place_forget()

        self.toggle_button(self.button3)

        label_destinataire4.grid(row=4, column=0)
        marge_horizontal = 20
        frame4.grid(row=2, column=0, sticky="NSEW", padx=marge_horizontal, pady=marge_horizontal)

    def toggle_button(self, button):
        if self.active_button:
            self.active_button.config()
        if self.active_button == button:
            self.active_button = None
        else:
            button.config()
            self.active_button = button

    def on_leave(self, event, button):
        if self.active_button != button:
            button.config()


def show_popup_menu(event):
    try:
        popup_menu.tk_popup(event.x_root, event.y_root, 0)
    finally:
        popup_menu.grab_release()

try:
    champ_message.bind("<Button-3>", show_popup_menu)

    # Just simply import the azure.tcl file
    fenetre.tk.call("source", "azure.tcl")

    if dark_mode == 1:
        fenetre.tk.call("set_theme", "dark")
    elif dark_mode == 0:
        fenetre.tk.call("set_theme", "light")

except Exception as e:
    messagebox.showerror("Theme Error", "An Error occur while setting the new theme: " + str(e))


def change_theme():
    theme_window = tk.Toplevel(fenetre)
    theme_window.title("choose theme")

    label_theme = ttk.Label(theme_window, text="Choose the theme")
    label_theme.pack()
    button_first_choice = ttk.Button(theme_window, text="Default", command=lambda: set_default_theme(theme_window))
    button_first_choice.pack(pady=5)
    button_second_choice = ttk.Button(theme_window, text="Dark Round", command=lambda: set_dark_theme(theme_window))
    button_second_choice.pack(pady=5)
    button_third_choice = ttk.Button(theme_window, text="Light Round", command=lambda: set_light_theme(theme_window))
    button_third_choice.pack(padx=50, pady=5)


def set_default_theme(theme_window):
    global dark_mode
    dark_mode = 3
    messagebox.showinfo("Restart to set theme", "You need to restart to set the theme")
    theme_window.destroy()


def set_light_theme(theme_window):
    try:
        global dark_mode
        dark_mode = 0
        fenetre.tk.call("set_theme", "light")
        theme_window.destroy()
    except Exception as e:
        messagebox.showerror("Theme Error", "An Error occur while setting the new theme: " + str(e))


def set_dark_theme(theme_window):
    try:
        global dark_mode
        dark_mode = 1
        fenetre.tk.call("set_theme", "dark")
        theme_window.destroy()
    except Exception as e:
        messagebox.showerror("Theme Error", "An Error occur while setting the new theme: " + str(e))


parameters_menu.add_command(label="Toggle light/dark theme", command=change_theme,
                            compound=LEFT)

toggle_key_visibility2()
app = ButtonApp(frame)

fenetre.mainloop()
