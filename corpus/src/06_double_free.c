/* 06_double_free.c — double free dans main(). */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    char *p = malloc(64);
    if (p == NULL)
        return 1;

    if (fgets(p, 64, stdin) == NULL)
        return 0;
    printf("Donnée : %s", p);

    free(p);
    free(p);

    char *q = malloc(64);
    char *r = malloc(64);
    printf("q=%p r=%p (identiques => tcache poisoning possible)\n",
           (void *)q, (void *)r);
    return 0;
}

/*
 * Notes :
 * - La glibc moderne détecte le double free dans le tcache -> SIGABRT.
 * - Sans détection, c'est la base du tcache poisoning : deux malloc
 *   successifs renvoient le même pointeur (q == r).
 * - Indépendant de canary/PIE/RELRO : le bug est dans l'allocateur.
 * - ASan signale « double-free » avec les deux traces de libération.
 * - Déclencher : echo AAAA | ./06_double_free_vuln
*/
