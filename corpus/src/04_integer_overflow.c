/* 04_integer_overflow.c — integer overflow sur un calcul de taille dans main(). */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    unsigned int count;

    if (fread(&count, sizeof(count), 1, stdin) != 1)
        return 0;

    /* count * 8u sur 32 bits : 0x20000001 * 8 = 0x100000008 tronqué -> 8. */
    size_t taille = count * 8u;
    unsigned long *tab = malloc(taille);
    if (tab == NULL)
        return 1;

    for (unsigned int i = 0; i < count; i++) {
        if (fread(&tab[i], sizeof(tab[i]), 1, stdin) != 1)
            break;
    }

    printf("%u éléments annoncés, allocation de %zu octets\n", count, taille);
    free(tab);
    return 0;
}

/*
 * Notes :
 * - Le « 8u » (pas « 8ul ») force le calcul sur 32 bits -> wrap possible.
 * - La boucle écrit count éléments dans une zone sous-allouée -> heap overflow.
 * - Ni canary, ni PIE, ni FORTIFY ne couvrent une allocation sous-dimensionnée.
 * - ASan signale « heap-buffer-overflow » ; CASR voit « negative-size-param ».
 * - Déclencher : python3 -c 'import sys; sys.stdout.buffer.write(b"\x01\x00\x00\x20"+b"A"*2000)' | ./04_integer_overflow_vuln
 */
