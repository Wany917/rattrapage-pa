/* 02_heap_bof.c — heap buffer overflow via read() non borné dans main(). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char *a = malloc(64);
    char *b = malloc(64);
    if (a == NULL || b == NULL)
        return 1;

    strcpy(b, "valeur_initiale_du_voisin");

    ssize_t n = read(STDIN_FILENO, a, 4096);
    if (n < 0)
        return 1;

    printf("Voisin après lecture : %s\n", b);

    free(a);
    free(b);
    return 0;
}

/*
 * Notes :
 * - read() lit 4096 octets dans un chunk de 64 -> écrasement du voisin « b ».
 * - La glibc détecte la corruption des métadonnées au free() -> SIGABRT.
 * - Les protections de pile (canary, PIE) n'y changent rien : le bug est
 *   sur le tas. FORTIFY ne borne pas read() ici non plus.
 * - Déclencher : python3 -c 'print("A"*200)' | ./02_heap_bof_vuln
 */
