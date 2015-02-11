/*
** herd.h for include in include
**
** Made by  aka
** Login   <>
**
** Started on  Sun 30 Nov 2014 11:55:43 AM CET 
** Last update Sun 30 Nov 2014 11:55:43 AM CET 
*/

#ifdef WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#define in_port_t u_short
#define ssize_t int
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#endif

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#ifndef	HERD_H_
# define HERD_H_

# define _unused __attribute__ ((unused))

// from herd to here: reference node by index in array. (check i >=0 && < MAX_NODES)
# define MAX_NODES				100
# define MAX_FP_LOCAL_CIRCS			100
# define MAX_FP_MIX_CIRCS			10000
# define MAX_QUEUE				50
# define MAX_NB_SECRETS				10 // max nb hops for client. this should be 1 for mixes.
# define AQ_BUFFER_MAX				512
# define HERD_PACKET_SIZE			400
# define HERD_SP_CLIENT_PACKET_SIZE		HERD_PACKET_SIZE + sizeof (struct sp_client_header)
# define HERD_SP_MANIFEST_PACKET_SIZE		HERD_PACKET_SIZE + sizeof (struct sp_manifest_header)
# define HERD_SECRET_SIZE			32
# define HERD_IV_SIZE				16

# define MAX_CH_CLIENTS				8

// for openssl EVP:
# define ENCRYPT				1
# define DECRYPT				0

// You'll need to declare: extern pthread_mutex_t log_lock;
# define LOG(format, ...) do {						\
		pthread_mutex_lock(&log_lock);				\
		fprintf(log_file, format "\n	-- %s:	%s:%d\n",	\
			##__VA_ARGS__ ,  __func__, __FILE__, __LINE__);	\
		fflush(log_file);					\
		pthread_mutex_unlock(&log_lock);			\
	} while (0)

// roles:
enum
{
	HERD_APP_PROXY = 0,
	HERD_MIX,
	HERD_SIP_DIR,
	HERD_RDV,
	HERD_SP,
	HERD_APP_PROXY_DUMMY,
};

enum
{
	HERD_CMD_INIT = 0,
	HERD_CMD_CONNECT_TO_NODE,
	HERD_CMD_OPEN_LOCAL_UDP,
	HERD_CMD_UPDATE_LOCAL_UDP_DEST,
	HERD_CMD_FORWARD,
	HERD_CMD_DATA,
	HERD_CMD_NEW_CIRCUIT,
	HERD_CMD_ACK,
	HERD_CMD_NEW_CLIENT,
	HERD_CMD_RM_NODE,
	HERD_CMD_NEW_MIX_FP,
	HERD_CMD_RM_MIX_FP,
	HERD_CMD_RM_LOCAL_UDP,
	HERD_CMD_UPDATE_ROLE,
	HERD_CMD_UPDATE_NODE_SECRET,
	HERD_CMD_PING,
};
#define HERD_CMD_REGISTER_ID_TO_SP	3

typedef					union
{
	struct sockaddr_storage		ss;
	struct sockaddr_in6		s6;
	struct sockaddr_in		s4;
}					addr;

struct					circ
{
	int				id;
	int				index; // for local fastpath: when in, index = local sock, when out, index of dtls sock. FIXME: no, if set it's always a dtls sock index.
	int				nb_secrets;
	uint8_t *			secrets[MAX_NB_SECRETS];
};

struct					local_fp
{
	int				used;
	int				fd;
	struct circ			circ_in;
	struct circ			circ_out;
	addr				local_in_peer;
	uint16_t			port;
	pthread_t			write_tid;
};

struct					mix_fp
{
	int				used;
	struct circ			circ_fwd;
	struct circ			circ_bwd;
};

struct					channel
{
	uint8_t *			client_secrets[MAX_CH_CLIENTS];
	int				client_node_index[MAX_CH_CLIENTS];
	int				used[MAX_CH_CLIENTS];
};

struct					node_info
{
	int				used;
	int				index;
	int				role;
	addr				peer_addr;
	addr				our_addr;
	pthread_t			write_tid;
	pthread_t			read_tid;
	pthread_mutex_t			ssl_lock;
	SSL *				ssl;
	pthread_mutex_t			queue_lock;
	uint8_t *			queue[MAX_QUEUE];
	int				queue_len[MAX_QUEUE];
	int				queue_head;
	int				queue_tail;
	int				cookie;
	int				fd;
	// for superpeers:
	uint8_t *			secret;
	int				client_index;

	// tmp, just ideas of what we might need:
	pthread_mutex_t			herd_lock; // for editing circuits and such
	uint8_t *			ntor_id;
	void *				open_circuits;
};

struct				sp_client
{
	int			local_index;
	int			id;
};

struct				sp_client_header
{
	uint8_t			iv[HERD_IV_SIZE];
	uint32_t		seq;
	uint32_t		msg_type;
} __attribute__ ((packed));

struct				sp_manifest_header
{
	//uint32_t		magic;
	struct sp_client_header	client[MAX_CH_CLIENTS];
} __attribute__ ((packed));

struct				state
{
	uint8_t *		cert_file;
	uint8_t *		key_file;
	int			ntor_sec_size;
	int			ntor_pub_size;
	int			ntor_id_size;
	uint8_t *		ntor_id;
	uint8_t *		ntor_sec;
	uint8_t *		ntor_pub;
	int			herd_dtls_port;
	int			herd_socket;
	int			role;
	addr			herd_peer;
	int			herd_peer_len;
	pthread_t		server_tid;
	const EVP_CIPHER *	cipher;
	// sp only:
	struct channel		channel;
	// things. might malloc these during init to make maxes configurable.
	struct node_info	nodes[MAX_NODES];
	struct local_fp		local_fp[MAX_FP_LOCAL_CIRCS];
	struct mix_fp		mix_fp[MAX_FP_MIX_CIRCS];
};


uint8_t *
mix_unxor(uint8_t *		message,
	  int			len,
	  struct channel *	channel);

int
xor_to_queue(struct node_info *		node,
	     int			client_index,
	     uint8_t *			client_msg);

int
send_cell_to_sp(uint8_t *	message,
		uint8_t *	secret,
		int		msg_type,
		int		node_index);

int
get_free_node(struct state *		state);

int
create_rated_write_thread(struct node_info *		node);

void
alloc_and_copy_string(uint8_t *		source,
		      uint8_t **	dest,
		      int		len);

void
print_state();

int
send_ack(uint32_t	cookie,
	 uint32_t	ret_value,
	 uint32_t	id);

int
send_data_packet(uint8_t *		msg,
		 int			len,
		 struct node_info *	node);

int
send_new_client(struct node_info *	node);

int
send_rm_node(struct node_info *	node);

int
process_fastpath(uint8_t *		message,
		 int			len,
		 struct node_info *	node);

int
process_init(uint8_t *		message,
	     int		len);

uint8_t *
parse_addr(uint8_t *		message,	// destructive on message.
	   int			len,		// FIXME: not using len because we know we set a 0 at the end of the buffer at the recvfrom. might change this.
	   addr *		dest);

int
process_connect_to_node(uint8_t *	message,
			int		len);

int
process_herd_message(uint8_t *	message,
		     int	len,
		     int	herd_socket,
		     addr *	herd_peer,
		     socklen_t	herd_peer_len);

#endif /* !HERD_H_ */
