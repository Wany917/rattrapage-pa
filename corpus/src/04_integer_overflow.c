/*
 * 04_integer_overflow.c : débordement d'entier sur un calcul de taille
 *
 * CLASSE     : integer overflow (multiplication de taille qui wrap sur 32 bits)
 * SOURCE     : fread(stdin) -> « count » (4 octets) puis les données
 * SINK       : boucle d'écriture dans « tab », sous-alloué à cause du wrap
 * FONCTION   : main()
 * POURQUOI   : la taille d'allocation est calculée par count * 8 sur un
 *              unsigned 32 bits. Un count élevé (ex : 0x20000001) fait wrapper
 *              le produit (0x100000008 tronqué -> 8) -> malloc trop petit. La
 *              boucle écrit ensuite « count » éléments -> débordement du tas.
 *              C'est la confusion classique « taille annoncée vs taille réelle ».
 * DÉCLENCHER : 4 octets de count qui font wrapper, suivis de données.
 *              python3 -c 'import sys; sys.stdout.buffer.write(b"\x01\x00\x00\x20"+b"A"*2000)' | ./04_integer_overflow_vuln
 *
 * COMPORTEMENT SELON LE PROFIL :
 *   _vuln : la boucle écrase les chunks voisins -> free() -> SIGABRT
 *           (ou SIGSEGV si l'écriture atteint une page non mappée).
 *   _prot : identique (le bug est un calcul d'entier ; ni canary, ni PIE, ni
 *           RELRO, ni FORTIFY ne couvrent une allocation sous-dimensionnée).
 *   _asan : « heap-buffer-overflow » signalé dès la première écriture hors de
 *           l'allocation.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    unsigned int count;

    /* Source : l'attaquant annonce un nombre d'éléments (4 octets bruts). */
    if (fread(&count, sizeof(count), 1, stdin) != 1)
        return 0;

    /*
     * BUG : count * 8 est évalué sur un unsigned 32 bits et peut wrapper.
     * Ex : 0x20000001 * 8 = 0x100000008, tronqué sur 32 bits -> 8 octets.
     * Écrire « 8u » (et non « 8ul ») force bien le calcul sur 32 bits.
     */
    size_t taille = count * 8u;
    unsigned long *tab = malloc(taille);
    if (tab == NULL)
        return 1;

    /* Sink : on écrit « count » éléments dans une zone trop petite. */
    for (unsigned int i = 0; i < count; i++) {
        if (fread(&tab[i], sizeof(tab[i]), 1, stdin) != 1)
            break;   /* plus de données disponibles (EOF) */
    }

    printf("%u éléments annoncés, allocation de %zu octets\n", count, taille);
    free(tab);
    return 0;
}
