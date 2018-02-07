#ifndef _TRUCE_T_H
#define _TRUCE_T_H

typedef struct _truce_secret
{
    unsigned char *secret;
    int secret_len;
    _truce_secret *next;
}truce_secret_t;

truce_secret_t *truce_get_secrets();

#endif
