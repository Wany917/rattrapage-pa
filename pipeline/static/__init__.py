"""Moteur d'analyse statique (vrai black-box : ne lit que le binaire).

Trois analyses complémentaires :
  - `dangerous_funcs` : repère les appels à des fonctions dangereuses (imports / PLT) ;
  - `buffer_sizing`   : compare la taille des buffers de pile à celle des copies ;
  - `taint`           : suit une donnée d'une source vers un sink (intra-procédural).
"""
