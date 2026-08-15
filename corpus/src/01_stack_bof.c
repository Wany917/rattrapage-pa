/*
 * 01_stack_bof.c : débordement de tampon sur la pile (stack buffer overflow)
 *
 * CLASSE     : stack buffer overflow (écrasement de l'adresse de retour, saved RIP)
 * SOURCE     : fgets(stdin) -> buffer statique « entree » (segment de données)
 * SINK       : strcpy(petit, entree) sans borne
 * FONCTION   : vuln(), copie vers « petit » (64 octets sur la pile)
 * POURQUOI   : strcpy copie jusqu'au '\0' sans vérifier la taille de la
 *              destination. Si l'entrée dépasse 64 octets, on écrit au-delà de
 *              « petit », sur le canary (s'il est présent), le RBP sauvé, puis
 *              l'adresse de retour.
 * NOTE       : la source est un buffer STATIQUE (pas une variable de pile) pour
 *              deux raisons : (1) source et destination ne se chevauchent pas,
 *              donc le débordement vise bien l'adresse de retour ; (2) aucun
 *              pointeur de pile n'est corrompu, le crash est un SIGSEGV « propre »
 *              au ret (contrôle de RIP net, idéal pour le PoC pwntools).
 * DÉCLENCHER : fournir sur stdin une ligne de plus de ~72 octets.
 *              python3 -c 'print("A"*200)' | ./01_stack_bof_vuln
 *
 * COMPORTEMENT SELON LE PROFIL :
 *   _vuln : pas de canary -> adresse de retour écrasée, SIGSEGV au ret
 *           (contrôle de RIP possible, cible du PoC pwntools).
 *   _prot : FORTIFY remplace strcpy par __strcpy_chk qui détecte le
 *           débordement -> abort (SIGABRT) ; le canary garderait aussi la main.
 *   _asan : AddressSanitizer signale « stack-buffer-overflow » avec la trace.
 */
#include <stdio.h>
#include <string.h>

static void vuln(void)
{
    char petit[64];

    /* Source : buffer statique (segment de données), pas sur la pile. */
    static char entree[1024];
    if (fgets(entree, sizeof(entree), stdin) == NULL)
        return;

    /* Sink : copie NON bornée vers « petit » -> débordement dès que l'entrée > 64. */
    strcpy(petit, entree);

    /* Effet de bord observable pour éviter que le compilateur n'élimine la copie. */
    printf("Reçu : %s", petit);
}

int main(void)
{
    vuln();
    return 0;
}
