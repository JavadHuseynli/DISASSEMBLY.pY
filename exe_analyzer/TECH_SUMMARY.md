# Quick Technology Summary 🚀

## Main Technologies Used

### 1. **Python 3.8+** 🐍
- **Nədir:** Proqramlaşdırma dili
- **Nə üçün:** Asan, güclü, çox kitabxana var
- **Harada:** Bütün kod faylları

### 2. **Tkinter** 🖥️
- **Nədir:** GUI framework (pəncərə, düymə yaratmaq üçün)
- **Nə üçün:** Python ilə gəlir, asan istifadə
- **Harada:** main.py - bütün visual hissə

### 3. **pefile** 📄
- **Nədir:** Windows .exe fayllarını oxumaq üçün
- **Nə üçün:** PE formatını parse etmək
- **Harada:** analyzer_core.py - fayl analizi

### 4. **Capstone** ⚙️
- **Nədir:** Disassembly engine (machine code → assembly)
- **Nə üçün:** Byte-ları assembly instruction-a çevirmək
- **Harada:** analyzer_core.py - disassembly

### 5. **Threading** 🔄
- **Nədir:** Arxa planda iş görmək
- **Nə üçün:** GUI donmasın
- **Harada:** main.py - analyze, disassemble

---

## Necə İşləyir? (Sadə izahat)

```
1. İstifadəçi düyməyə basır
        ↓
2. Tkinter event handler işə düşür
        ↓
3. analyzer_core.py faylı açır
        ↓
4. pefile PE strukturunu oxuyur
        ↓
5. Capstone byte-ları disassemble edir
        ↓
6. instruction_help.py izah göstərir
        ↓
7. Nəticə Tkinter pəncərəsində göstərilir
```

---

## Rənglər (Dark Theme) 🎨

```python
# Ən tünd
'#1e1e1e'  # Toolbar arxa plan

# Tünd
'#2b2b2b'  # Düymələr, pəncərələr

# Orta tünd
'#3c3c3c'  # Panellər

# Açıq tünd
'#404040'  # Hover, separator

# Yazılar
'#e0e0e0'  # Ağımtıl yazı
'#00ff00'  # Yaşıl (terminal style)
```

---

## Fayllar və Vəzifələri

| Fayl | Nə edir |
|------|---------|
| `main.py` | GUI (pəncərə, düymə, display) |
| `analyzer_core.py` | Analiz (parse, disassemble) |
| `ui_components.py` | Xüsusi widget-lər |
| `instruction_help.py` | İzahlar + diaqramlar |

---

## Əsas Anlayışlar

### PE Format
- Windows .exe/.dll fayllarının formatı
- Header, Section, Import, Export var

### Disassembly
- Machine code (48 83 EC 28) → Assembly (sub rsp, 0x28)
- Capstone bunu edir

### Cross-Reference (XRef)
- Hansı funksiya hansını çağırır
- Kod əlaqələri

### Visual Diagrams
- RAM və register dəyişikliklərini göstərir
- ASCII art ilə

---

## Quraşdırma

```bash
# Kitabxanalar
pip install pefile capstone dnfile

# İşə salma
python main.py
```

---

## Xüsusiyyətlər

✅ PE analizi (pefile)
✅ Disassembly (Capstone)
✅ Cross-reference (özümüz)
✅ İnteraktiv izahlar (instruction_help.py)
✅ Vizual diaqramlar (ASCII art)
✅ Dark theme (Tkinter colors)
✅ Zoom (font size dəyişmə)
✅ Multi-threading (donma yoxdur)

---

*Sadə izahat - bütün texnologiyalar*
