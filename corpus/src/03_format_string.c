/*
 * 03_format_string.c : chaîne de format contrôlée (format string)
 *
 * CLASSE     : format string (fuite via %p/%x, écriture via %n)
 * SOURCE     : fgets(stdin) -> « buf »
 * SINK       : printf(buf)  <-- « buf » est utilisé COMME chaîne de format
 * FONCTION   : main()
 * POURQUOI   : printf interprète les spécificateurs (%p, %x, %s, %n) présents
 *              dans « buf ». L'attaquant lit la pile (%p) ou écrit en mémoire
 *              (%n), alors que le format devrait être une constante.
 * DÉCLENCHER : fournir des spécificateurs sur stdin.
 *              printf '%p %p %p %p'   -> fuite d'adresses (leak)
 *              printf '%n%n%n%n'      -> écriture -> SIGSEGV
 *
 * COMPORTEMENT SELON LE PROFIL :
 *   _vuln : %p fuit la pile ; %n écrit à une adresse prise sur la pile ->
 *           SIGSEGV (ou primitive d'écriture arbitraire).
 *   _prot : -D_FORTIFY_SOURCE=2 remplace printf par __printf_chk, qui INTERDIT
 *           %n quand le format est en mémoire inscriptible -> abort. C'est
 *           l'illustration directe de l'effet de FORTIFY.
 *   _asan : ASan ne cible pas les format strings ; le crash éventuel reste
 *           visible via le signal (SIGSEGV).
 */
#include <stdio.h>

int main(void)
{
    char buf[256];

    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 0;

    /* Sink : format contrôlé par l'utilisateur (vulnérabilité). */
    printf(buf);
    printf("\n");
    return 0;
}
