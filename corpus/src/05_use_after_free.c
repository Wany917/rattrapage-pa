/* 05_use_after_free.c — UAF avec détournement de pointeur de fonction dans main(). */
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

    if (fgets(c->arg, sizeof(c->arg), stdin) == NULL)
        return 0;
    c->arg[strcspn(c->arg, "\n")] = '\0';

    free(c);

    /* Même taille -> le tcache recycle le chunk de c. */
    char *rejouer = malloc(sizeof(*c));
    if (rejouer == NULL)
        return 1;
    size_t lus = fread(rejouer, 1, sizeof(*c), stdin);
    (void)lus;

    c->handler(c->arg);

    free(rejouer);
    return 0;
}

/*
 * Notes :
 * - Après free(c), malloc(sizeof(*c)) recycle le même chunk via le tcache.
 *   En écrivant dans « rejouer », l'attaquant écrase c->handler (octets 32..39).
 * - PIE/RELRO/canary ne protègent pas ce scénario tas.
 * - ASan met le chunk en quarantaine et signale « heap-use-after-free ».
 * - Déclencher : { echo cmd; python3 -c 'import sys; sys.stdout.buffer.write(b"B"*40)'; } | ./05_use_after_free_vuln
 */
