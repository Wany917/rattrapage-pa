/* 03_format_string.c — format string via printf(buf) dans main(). */
#include <stdio.h>

int main(void)
{
    char buf[256];

    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 0;

    printf(buf);
    printf("\n");
    return 0;
}

/*
 * Notes :
 * - printf(buf) interprète les spécificateurs contrôlés par l'attaquant :
 *   %p/%x -> fuite de la pile, %n -> écriture arbitraire.
 * - _prot : FORTIFY remplace printf par __printf_chk, qui interdit %n quand
 *   le format est en mémoire inscriptible -> abort.
 * - ASan ne cible pas les format strings ; le crash éventuel reste visible
 *   via le signal (SIGSEGV).
 * - Déclencher : printf '%p %p %p %p' | ./03_format_string_vuln
 */
