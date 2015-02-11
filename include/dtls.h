/*
** dtls.h for include in include
**
** Made by  aka 
** Login   <>
**
** Started on  Sun 30 Nov 2014 12:01:52 PM CET 
** Last update Sun 30 Nov 2014 12:01:52 PM CET 
*/
#ifndef	DTLS_H_
# define DTLS_H_

unsigned long id_function(void);

int handle_socket_error();

# ifdef WIN32

DWORD WINAPI
connection_handle(LPVOID *info);

DWORD WINAPI
start_client(LPVOID *info);

DWORD WINAPI
start_server(LPVOID *info);

DWORD WINAPI
rated_write(LPVOID *info);

# else

void*
connection_handle(void *info);

void*
start_client(void *info);

void*
start_server(void *info);

void *
rated_write(void *arg);

# endif


#endif /* !DTLS_H_ */
