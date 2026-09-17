/* 01_stack_bof.c — stack buffer overflow dans vuln() via strcpy non borné. */
#include <stdio.h>
#include <string.h>

static void vuln(void)
{
    char petit[64];

    static char entree[1024];
    if (fgets(entree, sizeof(entree), stdin) == NULL)
        return;

    strcpy(petit, entree);

    printf("Reçu : %s", petit);
}

int main(void)
{
    vuln();
    return 0;
}

/*
 * Notes :
 * - La source est un buffer statique (pas sur la pile) pour que source et
 *   destination ne se chevauchent pas : le débordement vise proprement le
 *   saved RIP, ce qui donne un SIGSEGV net au ret (idéal pour le PoC).
 * - Offset buffer -> saved RIP : 72 octets (trouvé via cyclic pattern).
 * - _prot : FORTIFY remplace strcpy par __strcpy_chk -> abort avant le ret.
 * - Déclencher : python3 -c 'print("A"*200)' | ./01_stack_bof_vuln
 */
