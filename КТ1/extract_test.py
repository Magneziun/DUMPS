#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_test.py
Извлекает JPEG/PNG из Unit1.dfm и (если дан EXE) ответы из памяти
по VA 0x00477708 (25 dword).
Все ответы пишутся в один файл answers.txt в столбик: imgN - ответ
"""

import os, sys, struct, argparse

# ---- картинки ----
def extract_images(data: bytes, outdir: str):
    os.makedirs(outdir, exist_ok=True)
    i, n, idx = 0, len(data), 0
    while i < n:
        if data[i:i+3] == b'\xff\xd8\xff':                       # JPEG
            s = i; i += 3
            while i < n - 1:
                if data[i] == 0xFF and data[i+1] == 0xD9:
                    e = i + 2; idx += 1
                    open(f'{outdir}/img{idx}.jpg','wb').write(data[s:e])
                    print(f'[+] img{idx}.jpg ({e-s} байт)')
                    i = e; break
                i += 1
            else:
                i += 1
        elif data[i:i+8] == b'\x89PNG\r\n\x1a\n':                # PNG
            s = i; i += 8
            while i < n - 8:
                if data[i:i+8] == b'IEND\xaeB`\x82':
                    e = i + 8; idx += 1
                    open(f'{outdir}/img{idx}.png','wb').write(data[s:e])
                    print(f'[+] img{idx}.png ({e-s} байт)')
                    i = e; break
                i += 1
            else:
                i += 1
        else:
            i += 1
    return idx

# ---- чтение VA из PE ----
def read_va_int32(exe: str, va: int, count: int):
    d = open(exe,'rb').read()
    assert d[:2] == b'MZ', 'не PE'
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    assert d[pe:pe+4] == b'PE\0\0', 'не PE'
    coff = pe + 4
    nsec = struct.unpack_from('<H', d, coff + 2)[0]
    optsz = struct.unpack_from('<H', d, coff + 16)[0]
    optoff = coff + 20
    magic = struct.unpack_from('<H', d, optoff)[0]
    if magic == 0x10b:
        ib = struct.unpack_from('<I', d, optoff+28)[0]
    else:
        ib = struct.unpack_from('<Q', d, optoff+24)[0]
    rva = va - ib
    sec = optoff + optsz
    for i in range(nsec):
        o = sec + i*40
        vsz  = struct.unpack_from('<I', d, o+8)[0]
        va_s = struct.unpack_from('<I', d, o+12)[0]
        rsz  = struct.unpack_from('<I', d, o+16)[0]
        raw  = struct.unpack_from('<I', d, o+20)[0]
        if va_s <= rva < va_s + max(vsz, rsz):
            off = raw + (rva - va_s)
            return struct.unpack_from(f'<{count}i', d, off)
    raise ValueError(f'VA 0x{va:08X} не найдена')

def main():
    p = argparse.ArgumentParser()
    p.add_argument('dfm')
    p.add_argument('--exe')
    p.add_argument('--out-images',  default='images')
    p.add_argument('--out-answers', default='answers.txt')   # <- теперь файл, не папка
    a = p.parse_args()

    extract_images(open(a.dfm,'rb').read(), a.out_images)

    lines = []
    if a.exe:
        answers = read_va_int32(a.exe, 0x00477708, 60)   # индексы 0..25, берём 1..25
        for q in range(1, 60):
            lines.append(f'img{q} - {answers[q]}')
        print('\nОтветы из EXE:')
        for line in lines:
            print('  ' + line)
    else:
        for q in range(1, 60):
            lines.append(f'img{q} - <ANSWER>')
        print('\n[!] EXE не указан. Создан файл-заготовка. '
              'Запустите с --exe Project2.exe для автозаполнения.')

    with open(a.out_answers, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    print(f'\n[+] Все ответы сохранены в один файл: {a.out_answers}')

if __name__ == '__main__':
    main()