/*
 * 02_heap_bof.c : débordement de tampon sur le tas (heap buffer overflow)
 *
 * CLASSE     : heap buffer overflow (corruption du chunk voisin)
 * SOURCE     : read(stdin) -> chunk « a »
 * SINK       : read(0, a, 4096) alors que « a » ne fait que 64 octets
 * FONCTION   : main(), première allocation « a »
 * POURQUOI   : on lit jusqu'à 4096 octets dans un chunk de 64 -> on écrit
 *              au-delà de « a », sur les métadonnées et les données du chunk
 *              voisin « b ». La glibc détecte la corruption au moment du free.
 * DÉCLENCHER : fournir sur stdin plus de 64 octets.
 *              python3 -c 'print("A"*200)' | ./02_heap_bof_vuln
 *
 * COMPORTEMENT SELON LE PROFIL :
 *   _vuln : le voisin « b » est écrasé (valeur visible), puis free() déclenche
 *           « malloc(): corrupted... » -> SIGABRT. Les protections de pile
 *           (canary, PIE) ne changent rien : le bug est sur le tas.
 *   _prot : idem (RELRO/PIE/canary ne protègent pas le tas ; FORTIFY ne borne
 *           pas read() ici).
 *   _asan : AddressSanitizer signale « heap-buffer-overflow » dès l'écriture,
 *           avec l'allocation d'origine et la trace.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char *a = malloc(64);   /* chunk visé par le débordement */
    char *b = malloc(64);   /* chunk voisin, contient une donnée « sensible » */
    if (a == NULL || b == NULL)
        return 1;

    strcpy(b, "valeur_initiale_du_voisin");

    /* Sink : lecture NON bornée (4096) dans un chunk de 64 -> déborde sur « b ». */
    ssize_t n = read(STDIN_FILENO, a, 4096);
    if (n < 0)
        return 1;

    /* Montre la corruption du voisin. */
    printf("Voisin après lecture : %s\n", b);

    free(a);
    free(b);   /* la glibc détecte la corruption des métadonnées -> abort */
    return 0;
}
