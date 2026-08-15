/*
 * 05_use_after_free.c : utilisation après libération (use-after-free)
 *
 * CLASSE     : use-after-free (détournement de pointeur de fonction)
 * SOURCE     : fread(stdin) -> chunk recyclé « rejouer »
 * SINK       : c->handler(...) où « c » pointe sur de la mémoire libérée
 * FONCTION   : main(), après free(c)
 * POURQUOI   : après free(c), le chunk part dans le tcache. Un malloc de même
 *              taille (« rejouer ») recycle CE chunk. En écrivant dans
 *              « rejouer », on écrase c->handler (que « c » pointe toujours).
 *              L'appel c->handler() saute alors à une adresse contrôlée.
 * DÉCLENCHER : 1) une ligne pour c->arg (<= 31 octets), 2) 40 octets dont les
 *              octets 32..39 forment l'adresse détournée.
 *              { echo cmd; python3 -c 'import sys; sys.stdout.buffer.write(b"B"*40)'; } | ./05_use_after_free_vuln
 *
 * COMPORTEMENT SELON LE PROFIL :
 *   _vuln : le tcache recycle le chunk -> handler écrasé -> saut contrôlé,
 *           SIGSEGV si l'adresse est invalide.
 *   _prot : PIE/RELRO/canary ne protègent pas ce scénario tas ; même résultat.
 *   _asan : ASan met le chunk en quarantaine (pas de recyclage immédiat) et
 *           signale « heap-use-after-free » dès l'accès à c->handler.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct commande {
    char arg[32];
    void (*handler)(const char *);
};

static void afficher(const char *s)
{
    printf("[handler légitime] %s\n", s);
}

int main(void)
{
    struct commande *c = malloc(sizeof(*c));
    if (c == NULL)
        return 1;
    c->handler = afficher;

    /* Remplit c->arg depuis stdin. */
    if (fgets(c->arg, sizeof(c->arg), stdin) == NULL)
        return 0;
    c->arg[strcspn(c->arg, "\n")] = '\0';

    free(c);   /* libération : « c » devient un pointeur pendouillant (dangling) */

    /*
     * Réallocation de même taille : le tcache renvoie le chunk de « c ».
     * En écrivant dans « rejouer », l'attaquant réécrit c->handler.
     */
    char *rejouer = malloc(sizeof(*c));
    if (rejouer == NULL)
        return 1;
    size_t lus = fread(rejouer, 1, sizeof(*c), stdin);
    (void)lus;

    /* Sink : appel via un pointeur situé dans de la mémoire libérée (UAF). */
    c->handler(c->arg);

    free(rejouer);
    return 0;
}
