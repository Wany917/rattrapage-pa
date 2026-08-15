/*
 * 06_double_free.c : double libération (double free)
 *
 * CLASSE     : double free (corruption des bins / base du tcache poisoning)
 * SOURCE     : fgets(stdin) -> « p »
 * SINK       : free(p) appelé deux fois
 * FONCTION   : main()
 * POURQUOI   : libérer deux fois le même chunk corrompt les listes chaînées de
 *              l'allocateur. La glibc moderne détecte le cas simple (tcache) et
 *              abort ; sinon, c'est la base du « tcache poisoning » (faire
 *              renvoyer par malloc une adresse contrôlée).
 * DÉCLENCHER : n'importe quelle entrée ; le double free est inconditionnel.
 *              echo AAAA | ./06_double_free_vuln
 *
 * COMPORTEMENT SELON LE PROFIL :
 *   _vuln : « free(): double free detected in tcache 2 » -> SIGABRT.
 *   _prot : identique (protection tas, indépendante de canary/PIE/RELRO).
 *   _asan : ASan signale « double-free » avec les deux traces de libération.
 */
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
    free(p);   /* double free : détecté par le tcache -> abort (ou poisoning) */

    /* Illustre la primitive : après un double free non détecté, deux malloc
     * successifs peuvent renvoyer le même pointeur (tcache poisoning). */
    char *q = malloc(64);
    char *r = malloc(64);
    printf("q=%p r=%p (identiques => tcache poisoning possible)\n",
           (void *)q, (void *)r);
    return 0;
}
