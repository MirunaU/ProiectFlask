# Restaurant Rewards - Sistem de Loialitate Studenți

Această aplicație web este un sistem de gestionare a punctelor de loialitate, dezvoltat în Python folosind framework-ul **Flask**. Proiectul include un mecanism de securitate pentru validarea tranzacțiilor (Logică Anti-Fraudă) și roluri distincte pentru utilizatori.

## 📋 Funcționalități Principale

1. **Sistem de Autentificare:**
   - Login și Înregistrare securizată.
   - Hashing pentru parole (PBKDF2).
   - Roluri: **Student** (Client) și **Admin** (Personal Restaurant).

2. **Flux Tranzacțional Securizat (Anti-Fraudă):**
   - **Pasul 1 (Pending):** Studentul inițiază comanda. Punctele sunt blocate, statusul este "În așteptare".
   - **Pasul 2 (Served):** Administratorul verifică fizic prezența studentului și marchează comanda ca "Servită". Doar atunci tranzacția este finală.

3. **Audit:**
   - Sistem de logging pentru acțiunile critice (ștergeri, modificări sold).

## 🛠️ Cerințe de Sistem
- Python 3.8 sau mai nou.

## 🚀 Instrucțiuni de Instalare și Rulare

Urmați acești pași pentru a rula proiectul local:

1. **Configurarea Mediului:**
   Deschideți un terminal în folderul proiectului:
   ```bash
   python -m venv venv
   
   # Activare Windows:
   venv\Scripts\activate
   
   # Activare Mac/Linux (ignorați dacă sunteți pe Windows):
   # source venv/bin/activate

   pip install -r requirements.txt
   flask db upgrade
   flask run