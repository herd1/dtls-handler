/*
** herd.c for src in src
**
** Made by  aka
** Login   <>
**
** Started on  Sun 30 Nov 2014 11:54:59 AM CET 
** Last update Sun 30 Nov 2014 11:54:59 AM CET 
*/

#include "herd.h"
#include "dtls.h"

FILE *			log_file	= NULL;
struct state *		state		= NULL;
pthread_mutex_t		log_lock;
struct node_info *	mix		= NULL; // FIXME only used by SP, tmp hardcoded ugly thing.
struct local_fp *	ping_fp		= NULL; // FIXME only used by SP, tmp hardcoded ugly thing.
long			ping_count	= 0;
long			pong_count	= 0;


/***************************************************
** helper functions:
*/

int
get_free_node(struct state *		state_info)
{
	struct node_info *	nodes	= state_info->nodes;

	for (int i = 0; i < MAX_NODES; ++i)
		if (nodes[i].used == 0)
			return i;

	return -1;
}

void
free_circ(struct circ *		circ)
{
	for (int i = 0; i < circ->nb_secrets; ++i)
		free(circ->secrets[i]);
	memset(circ, 0, sizeof (struct circ));
}

void
free_node(int		index)
{
	struct node_info *	node;

	if (index < 0 || index >= MAX_NODES)
		return;

	node	= &state->nodes[index];

	pthread_cancel(node->read_tid);
	pthread_cancel(node->write_tid);

	pthread_mutex_lock(&node->queue_lock);
	for (int i = 0; i < MAX_QUEUE; ++i)
		free(node->queue[i]);
	pthread_mutex_unlock(&node->queue_lock);

	pthread_mutex_lock(&node->ssl_lock);
	SSL_shutdown(node->ssl);
	pthread_mutex_unlock(&node->ssl_lock);
	close(node->fd);

	pthread_mutex_destroy(&node->ssl_lock);
	pthread_mutex_destroy(&node->queue_lock);

	memset(node, 0, sizeof (struct node_info));

	node->index	= index;
}

int
add_secrets_to_circ(struct circ *	circ,
		    uint8_t *		message,
		    int			len)
{
	int	nb_secrets;

	if (4 > len)
		goto size_err;
	nb_secrets	= ntohl(*((uint32_t *) message));
	message		+= 4;
	len		-= 4;

	if (nb_secrets * HERD_SECRET_SIZE > len && nb_secrets <= MAX_NB_SECRETS)
		goto size_err;

	circ->nb_secrets	= nb_secrets;

	for (int i = 0; i < nb_secrets; ++i)
	{
		circ->secrets[i]	= malloc(HERD_SECRET_SIZE);
		if (!circ->secrets[i])
			goto this_is_the_end;
		memcpy(circ->secrets[i], message + i * HERD_SECRET_SIZE, HERD_SECRET_SIZE);
	}

	return nb_secrets * HERD_SECRET_SIZE + 4;

this_is_the_end:
	LOG("malloc failed, getting out of here.");
	exit(1);
size_err:
	LOG("size error adding secrets to circ");
	return -1;
}

int
create_rated_write_thread(struct node_info *		node)
{
	pthread_mutex_init(&node->queue_lock, NULL); // FIXME herd lock too.
	pthread_mutex_init(&node->ssl_lock, NULL); // FIXME herd lock too.
	return pthread_create(&node->write_tid, NULL, rated_write, node);
}

void
alloc_and_copy_string(uint8_t *		source,
		      uint8_t **	dest,
		      int		len)
{
	// and add terminating zero

	if (!(*dest = malloc(len + 1)))
	{
		LOG("malloc failed, getting out of here.");
		exit(1);
	}
	memcpy(*dest, source, len);
	(*dest)[len] = 0;
}


void
print_state()
{
	if (!state)
		return;
	LOG("cert_file: %s", state->cert_file);
	LOG("key_file: %s", state->key_file);
	//LOG("ntor_sec: %s", state->ntor_sec);
	//LOG("ntor_pub: %s", state->ntor_pub);
	LOG("herd_dtls_port: %i", state->herd_dtls_port);
}

uint8_t *
parse_addr(uint8_t *		message,	// destructive on message.
	   int			len,		// FIXME: not using len because we know we set a 0 at the end of the buffer at the recvfrom. might change this.
	   addr *		dest)
{
	int			i;
	uint8_t *		end;

	// always udp, so not reading proto specifier for now
	message += 2;
	len	-= 2;

	if (message[0] == '[')
	{
		// parse format [fe80:1234::1]:1234
		dest->ss.ss_family	= AF_INET6;
		++message;

		for (i = 0; message[i] != ']' && message[i]; ++i)
			;
		message[i] = 0;

		if (!inet_pton(AF_INET6, (char *) message, &dest->s6.sin6_addr))
			goto err;

		message += i + 2;
		dest->s6.sin6_port = strtol((char *) message, (char **) &end, 10);
	}
	else
	{
		// parse format 123.0.0.2:1234
		dest->ss.ss_family	= AF_INET;

		for (i = 0; message[i] != ':' && message[i]; ++i)
			;
		message[i] = 0;

		if (!inet_pton(AF_INET, (char *) message, &dest->s4.sin_addr))
			goto err;

		message += i + 1;
		dest->s4.sin_port = strtol((char *) message, (char **) &end, 10);
	}

	return end + 1; // index at which to continue parsing after the address.
err:
	return NULL;
}


/***************************************************
** crypto helpers:
*/

int
toggle_onion_skin(uint8_t *		in,
		  uint8_t *		out,
		  uint8_t *		key,
		  uint8_t *		iv,
		  int			len,
		  int			enc_or_dec)
{
	// For enc_or_dec use ENCRYPT or DECRYPT for clarity.
	EVP_CIPHER_CTX			ctx;
	int				outlen;
	char				err[256];

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	// last arg: 1 = enc, 0 = dec
	if (!EVP_CipherInit_ex(&ctx, state->cipher, NULL, key, iv, enc_or_dec))
		goto err;

	if (!EVP_CipherUpdate(&ctx, out, &outlen, in, len))
		goto err;

	if (!EVP_CipherFinal_ex(&ctx, out + outlen, &len))
		goto err;

	return outlen + len;

err:
	ERR_error_string_n(ERR_get_error(), err, 256);
	LOG("EVP error: %s", err);
	return -1;
}

uint8_t *
toggle_onion_skins(uint8_t *		in,
		   uint8_t *		out,
		   struct circ *	circ,
		   uint8_t *		iv,
		   int			len,
		   int			enc_or_dec)
{
	uint8_t *	tmp	= out;

	out	= in;
	in	= tmp;

	for (int i = 0; i < circ->nb_secrets; ++i)
	{
		tmp	= out;
		out	= in;
		in	= tmp;

		len	= toggle_onion_skin(in, out, circ->secrets[i], iv, len, enc_or_dec);
		if (len == -1)
			goto enc_fail;
	}

	return out;

enc_fail:
	return 0;
}


/***************************************************
** node queue helper:
*/

int
add_to_queue(int	node_index,
	     uint8_t *	message,
	     int	len)
{
	// FIXME: add locks everywhere to protect queue.
	struct node_info *	node;
	uint8_t **		queue;
	//int			size	= HERD_PACKET_SIZE;

	if (node_index < 0 || node_index >= MAX_NODES)
		goto err_out;

	node	= &state->nodes[node_index];

	if (!node->used)
		goto err_unused;

	//if (node->role == HERD_SP)
	//	size += sizeof (struct sp_client_header);

	//if (len != size)
	//	goto err_size;

	pthread_mutex_lock(&node->queue_lock);
	queue	= &node->queue[node->queue_tail];
	node->queue_len[node->queue_tail]	= len;

	if (*queue)
		goto err_queue;

	if (++node->queue_tail == MAX_QUEUE)
		node->queue_tail	= 0;

	*queue	= malloc(len);
	if (!*queue)
		goto doom;
	memcpy(*queue, message, len);
	pthread_mutex_unlock(&node->queue_lock);

	return 0;

doom:
	LOG("malloc failed, getting out of here.");
	exit(1);
err_unused:
	LOG("herd node id is unused: %i", node_index);
	return 3;
err_out:
	LOG("herd node id out of bounds: %i", node_index);
	return 2;
err_queue:
	pthread_mutex_unlock(&node->queue_lock);
	LOG("herd node id %i has a full queue", node_index);
	return 1;
//err_size:
//	LOG("herd node id %i was asked to send a packet with bad length = %i", node_index, len);
//	return 1;
}


/***************************************************
** Sending things to herd:
*/

int
send_ping_or_pong(struct node_info *	node,
		  struct local_fp *	fp,
		  uint8_t *		message,
		  int			ping_or_pong)
{
	uint8_t			buffer[HERD_PACKET_SIZE];
	uint8_t			ping[AQ_BUFFER_MAX]; // FIXME: this should be buffer - header sizes.
	struct timeval		tv;
	unsigned long		time	= 0;
	int			ping_len;

	ping_len	= sizeof (unsigned long);

	*(uint32_t *) buffer		= htonl(ping_len + 9 + HERD_IV_SIZE + 11);	// FIXME header sizes.
	*(uint32_t *) &buffer[4]	= htonl(fp->circ_out.id);
	buffer[8]			= 3;					//relay
	RAND_bytes(buffer + 9, HERD_IV_SIZE);

	uint8_t	*	iv		= buffer + 9;
	uint8_t	*	stream		= buffer + 25;

	stream[0]			= ping_or_pong;				// relay data
	*(uint16_t *) &stream[1]	= htons(0);				// recognized
	*(uint16_t *) &stream[3]	= htons(101);				// stream id
	*(uint32_t *) &stream[5]	= htonl(101);				// digest
	*(uint16_t *) &stream[9]	= htons(ping_len);			// size

	if (!message)
	{
		gettimeofday(&tv, NULL);
		time		= 1000000 * tv.tv_sec + tv.tv_usec;
		message		= (uint8_t*) &time;
	}
	//else
	//	memcpy(&time, message, sizeof (unsigned long)); // debug only FIXME

	memcpy(stream + 11, message, ping_len);
	uint8_t *	in		= stream;
	uint8_t *	out		= ping;

	if (!(out = toggle_onion_skins(in, out, &fp->circ_out, iv, ping_len + 11, ENCRYPT))) // FIXME will replace ping_len with HERD_PACKET_SIZE, this is tmp.// FIXME: also, encrypt whole packet len with padding, not just the user payload.
		goto enc_fail;

	memcpy(stream, out, ping_len + 11);

	if (fp->circ_out.index > MAX_NODES || fp->circ_out.index < 0)
		goto bad_node;

	//LOG("piiiiiiing sending on index %i, circ = %i, secs %i, sp = %i || %i \ntime: %lu, %i", node->index, fp->circ_out.nb_secrets, fp->circ_out.id, node->role == HERD_SP, ping_or_pong, time, *(uint8_t *) &time);
	send_cell_to_sp(buffer, node->secret, 1, node->index);

	return 0;

bad_node:
	LOG("node index is bad: %i", fp->circ_out.index);
	return 1;
enc_fail:
	LOG("encryption failed, dropping.");
	return 2;
}

int
process_ping_or_pong(struct node_info *	node _unused, // FIXME wtf
		     struct local_fp *	fp _unused,
		     uint8_t *		message)
{
	struct timeval		tv;
	unsigned long		time;
	unsigned long 		time_before;
	unsigned long 		delta;

	if (message[0] == 20) // pong
	{
		++pong_count;
		gettimeofday(&tv, NULL);
		time		= 1000000 * tv.tv_sec + tv.tv_usec;
		memcpy(&time_before, message + 11, sizeof (unsigned long));

		delta		= time - time_before;
		LOG("RTT: %lu us,  %lu ms", delta, delta / 1000);
		LOG("PING LOSS: %lu / %lu = %G", ping_count, pong_count, 1.0 * ping_count / pong_count);
		return 0;
	}

	if (ping_fp)
		return send_ping_or_pong(&state->nodes[1], ping_fp, message + 11, 20);
	//return send_ping_or_pong(&state->nodes[1], fp, NULL, 19);

	LOG("no fp");
	return 3;
}

int
send_ack(uint32_t	cookie,
	 uint32_t	ret_value,
	 uint32_t	id)
{
	char		buffer[13];
	int		len;
	int		total = sizeof (buffer);

	buffer[0]	= HERD_CMD_ACK;
	cookie		= htonl(cookie);
	ret_value	= htonl(ret_value);
	id		= htonl(id);
	memcpy(buffer + 1, &cookie, 4);
	memcpy(buffer + 5, &ret_value, 4);
	memcpy(buffer + 9, &id, 4);

	len		= sendto(state->herd_socket, buffer, total, 0, (struct sockaddr * restrict) &state->herd_peer, state->herd_peer_len);

	if (len != total)
		LOG("Something went wrong sending ACK.");
	return total - len;
}

int
send_data_packet(uint8_t *		msg,
		 int			len,
		 struct node_info *	node)
{
	int			index;
	int			sent;
	char			buf[HERD_SP_MANIFEST_PACKET_SIZE + 5];

	if (len != HERD_PACKET_SIZE)
		LOG("Warning: packet is of unexpected size %i", len);

	buf[0]	= HERD_CMD_DATA;
	index	= htonl(node->index);
	memcpy(buf + 1, &index, 4);
	memcpy(buf + 5, msg, len);
	len	+= 5;
	sent	= sendto(state->herd_socket, buf, len, 0, (struct sockaddr * restrict) &state->herd_peer, state->herd_peer_len);
	LOG("SENT TO HERD :: %i", sent);

	if (len != sent)
		LOG("Something went wrong sending data packet.");

	return sent - len;
}

int
send_new_client(struct node_info *	node)
{
	char				buf[10];
	int				to_copy;
	int				sent;
	// might also send peer info

	buf[0]	= HERD_CMD_NEW_CLIENT;
	to_copy	= htonl(node->index);
	memcpy(buf + 1, &to_copy, 4);

	sent	= sendto(state->herd_socket, buf, 5, 0, (struct sockaddr * restrict) &state->herd_peer, state->herd_peer_len);

	if (5 == sent)
		return 0;

	LOG("Something went wrong sending new client message, node index: %i", node->index);
	return 1;
}

int
send_rm_node(struct node_info *	node)
{
	char				buf[10];
	int				to_copy;
	int				sent;
	// might also send peer info

	buf[0]	= HERD_CMD_RM_NODE;
	to_copy	= htonl(node->index);
	memcpy(buf + 1, &to_copy, 4);

	sent	= sendto(state->herd_socket, buf, 5, 0, (struct sockaddr * restrict) &state->herd_peer, state->herd_peer_len);

	if (5 == sent)
		return 0;

	LOG("Something went wrong sending rm client message, node index: %i", node->index);
	return 1;
}

int
send_local_udp_ack(uint32_t		cookie,
		   uint32_t		index,
		   uint16_t		port) // expecting the port in network byte order, but not index nor cookie. might change this...
{
	char				buf[11];
	int				sent;

	buf[0]	= HERD_CMD_ACK;
	index	= htonl(index);
	cookie	= htonl(cookie);
	memcpy(buf + 1, &cookie, 4);
	memcpy(buf + 5, &index, 4);
	memcpy(buf + 9, &port, 2);

	sent	= sendto(state->herd_socket, buf, 11, 0, (struct sockaddr * restrict) &state->herd_peer, state->herd_peer_len);

	if (11 == sent)
		return 0;

	LOG("Something went wrong sending rm client message, node index: %i", index);
	return 1;
}

// int
// reply_to_ping(uint8_t *			message,
// 	      int			len,
// 	      struct circ *		circ,
// 	      struct node_info *	node)
// {
// 	return 0;
// }


/***************************************************
** fastpath, for app proxy:
*/

#ifdef WIN32
DWORD WINAPI
forward_to_circ(LPVOID *	info)
{
#else
void *
forward_to_circ(void *	info)
{
#endif
	// This functions reads data from a local socket (RTP stream),
	// adds a circ header, encrypts and forwards it to the appropriate
	// node.
	struct local_fp	*	fp	= info;
	uint8_t			buffer[HERD_PACKET_SIZE];
	uint8_t			read_buffer[AQ_BUFFER_MAX]; // FIXME: this should be buffer - header sizes.
	addr			peer;
	socklen_t		addrlen;

recover_from_err:
	while (1)
	{
		addrlen			= sizeof (peer);
		int	read_len	= recvfrom(fp->fd, read_buffer, AQ_BUFFER_MAX, MSG_WAITALL, (struct sockaddr * restrict) &peer, &addrlen);

		if (read_len < 0)
			goto read_err;
		if (read_len == (AQ_BUFFER_MAX - 1))
			LOG("WARNING: buffer totally filled %i", read_len);
		if (read_len < 0)
			goto read_err;
		if (read_len == 0)
			goto zero_fail;

		*(uint32_t *) buffer		= htonl(read_len + 9 + HERD_IV_SIZE + 11);	// FIXME header sizes.
		*(uint32_t *) &buffer[4]	= htonl(fp->circ_out.id);
		buffer[8]			= 3;					//relay
		RAND_bytes(buffer + 9, HERD_IV_SIZE);

		uint8_t	*	iv		= buffer + 9;
		uint8_t	*	stream		= buffer + 25;

		stream[0]			= 2;					// relay data
		*(uint16_t *) &stream[1]	= htons(0);				// recognized
		*(uint16_t *) &stream[3]	= htons(101);				// stream id
		*(uint32_t *) &stream[5]	= htonl(101);				// digest
		*(uint16_t *) &stream[9]	= htons(read_len);			// size

		if (read_len > AQ_BUFFER_MAX - 11 - 20) // 11 = stream, 20 = circ
			goto too_big_fail;

		memcpy(stream + 11, read_buffer, read_len);
		uint8_t *	in		= stream;
		uint8_t *	out		= read_buffer;

		if (!(out = toggle_onion_skins(in, out, &fp->circ_out, iv, read_len + 11, ENCRYPT))) // FIXME will replace read_len with HERD_PACKET_SIZE, this is tmp.// FIXME: also, encrypt whole packet len with padding, not just the user payload.
			goto enc_fail;

		memcpy(stream, out, read_len + 11);

		if (fp->circ_out.index > MAX_NODES || fp->circ_out.index < 0)
			goto bad_node;

		//struct node_info	* node	= &state->nodes[fp->circ_out.index];
		struct node_info	* node	= &state->nodes[1];

		if (node->role == HERD_SP)
			send_cell_to_sp(buffer, node->secret, 1, node->index); // FIXME null = secret. maybe we should put it in the node?
		else
			add_to_queue(fp->circ_out.index, buffer, HERD_PACKET_SIZE);
	}

	// errors from inside the while loop that lead to dropped packet, but listening goes on:
bad_node:
	LOG("node index is bad: %i", fp->circ_out.index);
	goto recover_from_err;
zero_fail:
	LOG("read zero, this shouldn't happen.");
	goto recover_from_err;
enc_fail:
	LOG("encryption failed, dropping.");
	goto recover_from_err;
too_big_fail:
	LOG("received a too big packet, dropping.");
	goto recover_from_err;

	// no recovery error:
read_err:
	// FIXME: add cleanup. memset 0 where needed.
	LOG("recvfrom: %s", strerror(errno));
	return NULL; // just to remove the warning
}

int
process_sp_fastpath(uint8_t *		message,
		    int			len,
		    struct node_info *	node)
{
	struct channel *		channel = &state->channel;
	int				client_index;
	int				actual_len;
	int				circ_id;
	int				cmd;
	int				circ_cmd;

//	LOG("sp fp: node role == %i, index: %i", node->role, node->index);

	if (node->role == HERD_MIX)
	{
		for (int i = 0; i < MAX_CH_CLIENTS; ++i)
			if (channel->used[i])
				add_to_queue(channel->client_node_index[i], message, len);
		return 0;
	}

	if (len != HERD_SP_CLIENT_PACKET_SIZE)
	{
		actual_len	= ntohl(*((uint32_t *) message));

		if (len < actual_len) // FIXME, not sure yet.
			goto size_err;

		circ_id		= ntohl(*((uint32_t *) &message[4]));
		circ_cmd	= message[8];
		cmd		= message[9];

		//LOG("l%i a%i", len, actual_len);
		//LOG("cid0? %i, 21? %i, cmd %i", circ_cmd, circ_cmd, cmd);

		if (circ_id != 0 || circ_cmd != 21 || cmd != HERD_CMD_REGISTER_ID_TO_SP)
			goto bad_data;

		node->client_index	= ntohl(*((uint32_t *) &message[10]));
		state->channel.used[node->client_index]	= 1;
		state->channel.client_node_index[node->client_index]	= node->index;
		LOG("added app-proxy node index %i, as client index %i", node->index, node->client_index);

		return 0;
	}

	// FIXME: tmp, doing this because for now SP only has one channel
	if (!mix)
		for (int i = 0; i < MAX_NODES && !mix; ++i)
			if (state->nodes[i].role == HERD_MIX)
				mix	= &state->nodes[i];

	client_index	= node->client_index;
	xor_to_queue(mix, client_index, message);
	return 0;

bad_data:
	LOG("unexpected data in packet");
	return 2;
size_err:
	LOG("size error %i vs %i: while reading packet", actual_len, len);
	return 1;
}

int
process_fastpath(uint8_t *		message,
		 int			len,
		 struct node_info *	node)
{
	// Takes a packet received from dtls, removes encryption & cell headers, forwards to local udp socket.
	int			circ_id;
	int			actual_len	= -1;
	int			initial_len	= len;
	int			cmd;
	uint8_t *		relay_cell;
	struct local_fp *	fp		= 0;
	struct mix_fp *		mfp		= 0;
	struct circ *		circ		= 0;
	int			err		= 0;
	int			enc_or_dec	= DECRYPT; // Default for app-proxy
	int			recognized;
	uint8_t			in[AQ_BUFFER_MAX];
	uint8_t			buffer[AQ_BUFFER_MAX];
	uint8_t *		out		= buffer;
	uint8_t *		iv;

	if (state->role == HERD_SP)
		return process_sp_fastpath(message, len, node);

	//LOG("bool: %i %i len %i", state->role == HERD_MIX, node->role == HERD_SP, len);

	if (state->role == HERD_MIX && node->role == HERD_SP)
	{
		if (!(message	= mix_unxor(message, len, &state->channel)))
			goto padding;
		len	-= sizeof (struct sp_manifest_header);
	}

	if (0 >= len)
		goto net_err;
	if (4 > len)
		goto size_err;

	actual_len	= ntohl(*((uint32_t *) message));

	if (len < actual_len) // FIXME, not sure yet.
		goto size_err;

	circ_id		= ntohl(*((uint32_t *) (message + 4)));
	cmd		= message[8];
	if (cmd == 0)
		goto padding;
	if (cmd != 3) // relay == 3
		goto not_relay;
	// FIXME if circ_id not recognized & packet doesn't make sense (create/created?) we should drop it
	// otherwise a client's herd will be spammed by undecipherable padding packets.

	if (state->role == HERD_APP_PROXY)
	{
		for (int i = 0; i < MAX_FP_LOCAL_CIRCS && !fp; ++i)
			if (state->local_fp[i].circ_in.id == circ_id)
				fp	= &state->local_fp[i];

		if (!fp)
			goto no_fp;

		circ	= &fp->circ_in;
	}
	else
	{
		for (int i = 0; i < MAX_FP_MIX_CIRCS && !mfp; ++i)
			if (state->mix_fp[i].circ_fwd.id == circ_id || state->mix_fp[i].circ_bwd.id == circ_id)
				mfp	= &state->mix_fp[i];

		if (!mfp)
			goto no_fp;

		if (node->index != mfp->circ_fwd.index)
		{
			circ		= &mfp->circ_fwd;
			enc_or_dec	= DECRYPT;
		}
		else
		{
			circ		= &mfp->circ_bwd;
			enc_or_dec	= ENCRYPT;
		}
		//LOG("nb_secs %i", circ->nb_secrets);
	}

	iv		= message + 9;
	relay_cell	= iv + HERD_IV_SIZE;
	len		= actual_len - 9 - HERD_IV_SIZE;
	//LOG("init_len; %i, actual_len %i, len: %i", initial_len, actual_len, len);

	memcpy(in, relay_cell, len);

	if (!(out = toggle_onion_skins(in, out, circ, iv, len, enc_or_dec)))
		goto evp_err;

	// the place holder for digest:
	recognized	= 101 == ntohs(*(uint16_t *) &out[3]) && 101 == ntohl(*(uint32_t *) &out[5]) && !ntohs(*(uint16_t *) &out[1]);

	if (state->role == HERD_APP_PROXY)
	{
		if (fp && (out[0] == 20 || out[0] == 19)) // ping pong
			return process_ping_or_pong(&state->nodes[1], fp, out);

		if (!recognized)
			goto not_recognized;

		if (out[0] != 2)
			goto not_relay_data;

		actual_len	= ntohs(*(uint16_t *) &out[9]);

		out		+= 11; // we don't need that header anymore

		if (actual_len > len - 11)
			goto actual_len_err;

		actual_len	= sendto(fp->fd, out, actual_len, 0, (struct sockaddr * restrict) &fp->local_in_peer, sizeof (addr));

		if (actual_len != len)
			goto sent_len_err;
	}
	else
	{
		if (recognized)
			goto recognized;

		memcpy(relay_cell, out, len);
		add_to_queue(circ->index, message, initial_len);
		//LOG("recvd on node %i, sent on %i", node->index, circ->index);
	}

	return 0;

net_err:
	LOG("Network error: len = %i: %s", len, strerror(errno));
	return 6;
padding:
	LOG("Fastpath: circ = %i: dropping padding.", circ_id);
	return 5;
sent_len_err:
	//LOG("Fastpath: circ = %i: Sent packet, but returned bad len: %i vs %i", circ_id, actual_len, len);
	return 4;
actual_len_err:
	LOG("Fastpath, circ = %i, bad len: givenlen = %i, maxlen = %i, len = %i", circ_id, actual_len, len - 11 - 2, len);
	err	= 1;
	goto forward;
size_err:
	LOG("Fastpath, size error, forwarding to herd. len = %i, alen = %i", len, actual_len); // or drop? attacker could intentionally set wrong sizes to see it go through herd for some reason?
	err	= 2;
	goto forward;
evp_err:
	LOG("Fastpath, circ = %i, failed to decrypt", circ_id);
	err	= 3;
	goto forward;
not_relay_data:
	LOG("Fastpath, not a relay data cmd, circ = %i, cmd = %i", circ_id, out[0]);
	goto forward;
not_recognized:
	LOG("Fastpath, not recognized, circ = %i", circ_id);
	goto forward;
recognized:
	LOG("Fastpath, relay recognized, sending to herd for processing, circ = %i", circ_id);
	goto forward;
no_fp:
	LOG("Fastpath, no fastpath found, circ = %i", circ_id);
	goto forward;
not_relay:
	LOG("Fastpath, not a relay packet");
forward:
	LOG("FIXME length i%i l%i a%i", initial_len, len, actual_len);
	send_data_packet(message, initial_len, node);
	return err;
}


/***************************************************
** superpeer:
*/

void
xor(uint8_t *		result,
    uint8_t const *	in,
    int			len)
{
	// FIXME naive. will optimise later.
	for (int i = 0; i < len; ++i)
		result[i]	^= in[i];
}

int
xor_to_queue(struct node_info *		node,
	     int			client_index,
	     uint8_t *			client_msg)
{
	struct sp_manifest_header *	header	= 0;
	uint8_t *			payload	= 0;

	pthread_mutex_lock(&node->queue_lock);

	for (int i = node->queue_head; i < node->queue_tail && i < MAX_QUEUE && !header; ++i)
	{
		header	= (struct sp_manifest_header *) node->queue[i];
		if (header->client[client_index].seq)
			header = NULL;
	}
	if (!header && node->queue_tail < node->queue_head)
		for (int i = 0; i < node->queue_tail && !header; ++i)
		{
			header	= (struct sp_manifest_header *) node->queue[i];
			if (header->client[client_index].seq)
				header = NULL;
		}

	if (!header && node->queue[node->queue_tail])
		goto full_queue;

	if (!header)
	{
		header	= calloc(1, HERD_SP_MANIFEST_PACKET_SIZE);
		payload	= ((uint8_t *) header) + sizeof (struct sp_manifest_header);

		memcpy(&header->client[client_index], client_msg, sizeof (struct sp_client_header));
		memcpy(payload, client_msg + sizeof (struct sp_client_header), HERD_PACKET_SIZE); // FIXME check sizes
		node->queue[node->queue_tail]		= (uint8_t *) header;
		node->queue_len[node->queue_tail]	= HERD_SP_MANIFEST_PACKET_SIZE;
		if (++node->queue_tail == MAX_QUEUE)
			node->queue_tail	= 0;
	}
	else
	{
		payload	= ((uint8_t *) header) + sizeof (struct sp_manifest_header);
		memcpy(&header->client[client_index], client_msg, sizeof (struct sp_client_header));
		xor(payload, client_msg + sizeof (struct sp_client_header), HERD_PACKET_SIZE);
	}

	pthread_mutex_unlock(&node->queue_lock);

	return 0;

full_queue:
	pthread_mutex_unlock(&node->queue_lock);
	LOG("full queue, dropping.");
	return 1;
}

int
sp_unxor(uint8_t *			payload,
	 int				len _unused, // FIXME should always be HERD_PACKET_SIZE + header.
	 struct sp_client_header *	header,
	 uint8_t *			key)
{
	uint8_t				out[HERD_PACKET_SIZE + 4];
	uint8_t				in[HERD_PACKET_SIZE + 4];

	// 1 check header's msg type first:
	memcpy(in, &header->msg_type, 4);
	if (-1 == toggle_onion_skin(in, out, key, header->iv, 4, DECRYPT))
	    goto err;

	header->msg_type	= ntohl(*(uint32_t *) out);
	if (header->msg_type) // FIXME: this will change when msg_types are added
		return 0;

	// generate expected padding packet with seq:
	memset(in, 0, HERD_PACKET_SIZE + 4);
	memcpy(in, out, 4); // msg_type
	memcpy(in + 4, &header->seq, 4);

	if (-1 == toggle_onion_skin(in, out, key, header->iv, HERD_PACKET_SIZE + 4, ENCRYPT))
	    goto err;

	xor(payload, out + 4, HERD_PACKET_SIZE);

	return 0;

err:
	LOG("Encryption error");
	return 1;
}

uint8_t *
mix_unxor(uint8_t *		message,
	  int			len,
	  struct channel *	channel)
{
	struct sp_manifest_header *	header	= (struct sp_manifest_header *) message;
	uint8_t *			payload	= message + sizeof (struct sp_manifest_header);
	static const uint8_t		zero[HERD_PACKET_SIZE]	= { 0 };
	uint8_t				out[HERD_PACKET_SIZE];

	if (len != HERD_SP_MANIFEST_PACKET_SIZE)
		goto size_err;

	for (int i = 0; i < MAX_CH_CLIENTS; ++i) // FIXME tmp 3
	{
		if (header->client[i].seq && sp_unxor(payload, len, &header->client[i], channel->client_secrets[i]))
			goto enc_err;
	}

	for (int i = 0; i < MAX_CH_CLIENTS; ++i) // FIXME tmp 3
		if (header->client[i].msg_type)
		{
			toggle_onion_skin(payload - 4, out, channel->client_secrets[i], header->client[i].iv, HERD_PACKET_SIZE + 4, DECRYPT);
			memcpy(payload, out + 4, HERD_PACKET_SIZE);
			//LOG("client %i decrypt!", i);

			return payload;
		}

	if (!memcmp(payload, zero, HERD_PACKET_SIZE)) // means everyone sent padding data
		return NULL;

	return payload;

	return 0;

size_err:
	LOG("bad size %i", len);
enc_err:
	return NULL;
}

int
send_cell_to_sp(uint8_t *	message,
		uint8_t *	secret,
		int		msg_type,
		int		node_index)
{
	uint8_t				in[HERD_SP_CLIENT_PACKET_SIZE];
	uint8_t				out[HERD_PACKET_SIZE + 4];
	struct sp_client_header *	header	= (struct sp_client_header *) in;
	uint8_t *			payload	= sizeof (struct sp_client_header) + in;

	memset(in, 0, HERD_SP_CLIENT_PACKET_SIZE);

	// prepare header:
	RAND_bytes((uint8_t *)&header->seq, 4);
	RAND_bytes((uint8_t *)&header->iv, HERD_IV_SIZE);
	header->msg_type = htonl(msg_type);

	// prepare payload:
	if (!msg_type) // FIXME: different things will have to be done with msg_types
		memcpy(payload, &header->seq, 4);
	else
		memcpy(payload, message, HERD_PACKET_SIZE);

	// payload - 4 because we are encrypting msg_type too
	if (-1 == toggle_onion_skin(payload - 4, out, secret, header->iv, HERD_PACKET_SIZE + 4, ENCRYPT))
		goto err;
	memcpy(payload - 4, out, HERD_PACKET_SIZE + 4);

//	LOG("added manifest on node %i", node_index);
	return add_to_queue(node_index, in, HERD_SP_CLIENT_PACKET_SIZE);
err:
	LOG("err toggle_onion_skin");
	return 1;
}


/***************************************************
** process messages from herd:
*/

int
process_ping(uint8_t *	message,
	     int	len)
{
	int			circ_id;
	struct local_fp *	fp = NULL;

	if (4 > len)
		goto size_err;
	circ_id	= ntohl(*((uint32_t *) message));
	len	-= 4;
	message	+= 4;

	for (int i = 0; i < MAX_FP_LOCAL_CIRCS && !fp; ++i)
		if (state->local_fp[i].circ_out.id == circ_id)
			fp	= &(state->local_fp[i]);

	if (!fp)
		goto bad_circ;
	ping_fp		= fp; // FIXME ugly, getting lazy, deadline a few hours awayw

	++ping_count;

	return send_ping_or_pong(&state->nodes[1], fp, NULL, 19);

size_err:
	LOG("packet too small %i", len);
	return 2;
bad_circ:
	LOG("could not find circuit %i", circ_id);
	return 1;
}

int
process_init(uint8_t *		message,
	     int		len)
{
	uint16_t		size;

	if (state)
	{
		LOG("Something is wrong: herd is asking us to re-init state.");
		goto err;
	}

	state	= calloc(1, sizeof (struct state));
	for (int i = 0; i < MAX_NODES; ++i)
		state->nodes[i].index	= i;

	state->role	= message[0];
	++message;
	--len;
	if (state->role != HERD_SP && state->role != HERD_APP_PROXY && state->role != HERD_APP_PROXY_DUMMY)
		state->role	= HERD_MIX;
	LOG("Initialising dtls-handler as %s", state->role == HERD_APP_PROXY ? "App-Proxy" : "Mix");

	size	= ntohs(*((uint16_t *) message));
	if (size + 2 > len)
		goto size_err;
	len	-= size + 2;

	message += 2;
	alloc_and_copy_string(message, &(state->cert_file), size);
	message += size;

	size	= ntohs(*((uint16_t *) message));
	if (size + 2 > len)
		goto size_err;
	len	-= size + 2;
	message += 2;
	alloc_and_copy_string(message, &(state->key_file), size);
	message += size;

	size	= ntohs(*((uint16_t *) message));
	if (size + 2 > len)
		goto size_err;
	len	-= size + 2;
	message += 2;
	alloc_and_copy_string(message, &(state->ntor_pub), size);
	state->ntor_pub_size = size;
	message += size;

	size	= ntohs(*((uint16_t *) message));
	if (size + 2 > len)
		goto size_err;
	len	-= size + 2;
	message	+= 2;
	alloc_and_copy_string(message, &(state->ntor_sec), size);
	state->ntor_sec_size	= size;
	message	+= size;

	size	= ntohs(*((uint16_t *) message));
	if (size + 2 > len)
		goto size_err;
	len	-= size + 2;
	message	+= 2;
	alloc_and_copy_string(message, &(state->ntor_id), size);
	state->ntor_id_size	= size;
	message	+= size;

	if (2 > len)
		goto size_err;
	state->herd_dtls_port	= ntohs(*((uint16_t *) message));

	print_state();

	if (pthread_create(&state->server_tid, NULL, start_server, state) != 0)
	{
		perror("pthread_create");
		exit(-1);
	}
	LOG("successfully created listening server thread");
	state->cipher		= EVP_get_cipherbyname("aes-256-ctr");
	if (!state->cipher)
		goto cipher_err;

	return 0;

cipher_err:
	perror("EVP_get_cipherbyname()");
	LOG("couldn't get cipher");
	goto clean_err;
size_err:
	LOG("given size longer than buffer, %i", len);
clean_err:
	fflush(log_file);
	free(state->cert_file);
	free(state->key_file);
	free(state->ntor_pub);
	free(state->ntor_sec);
	free(state);
	state	= NULL;

err:
	return 1;
}

int
process_new_mix_fp(uint8_t *		message,
		   int			len)
{
	struct mix_fp *			fp		= NULL;
	int				circ_id_fwd;
	int				circ_id_bwd;
	int				index_fwd;
	int				index_bwd;
	int				added_len;

	if (4 > len)
		goto size_err;
	index_fwd	= ntohl(*((uint32_t *) message));
	len		-= 4;
	message		+= 4;

	if (index_fwd < 0 || index_fwd >= MAX_NODES)
		goto index_err;

	if (4 > len)
		goto size_err;
	index_bwd	= ntohl(*((uint32_t *) message));
	len		-= 4;
	message		+= 4;

	if (index_bwd < 0 || index_bwd >= MAX_NODES)
		goto index_err;

	if (4 > len)
		goto size_err;
	circ_id_fwd	= ntohl(*((uint32_t *) message));
	len		-= 4;
	message		+= 4;

	if (4 > len)
		goto size_err;
	circ_id_bwd	= ntohl(*((uint32_t *) message));
	len		-= 4;
	message		+= 4;

	for (int i = 0; i < MAX_FP_MIX_CIRCS; ++i)
	{
		if (state->mix_fp[i].circ_fwd.id == circ_id_fwd ||
		    state->mix_fp[i].circ_fwd.id == circ_id_bwd ||
		    state->mix_fp[i].circ_bwd.id == circ_id_fwd ||
		    state->mix_fp[i].circ_bwd.id == circ_id_bwd) // FIXME once we implement circ ids like in tor, we won't be able to mistake a fwd for a bwd.
		{
			free_circ(&state->mix_fp[i].circ_fwd);
			free_circ(&state->mix_fp[i].circ_bwd);
			LOG("Herd asked to create a FP for a circuit that already exists. Probably means herd neglected to free it.");
		}
		if (!fp && !state->mix_fp[i].used)
			fp = &state->mix_fp[i];
	}
	if (!fp)
		goto no_fp;

	LOG("Adding mix FP with fwd = %i, bwd = %i [circ ids]", circ_id_fwd, circ_id_bwd);

	added_len	= add_secrets_to_circ(&fp->circ_fwd, message, len);
	if (added_len == -1)
		goto sec_err;
	message		+= added_len;
	len		-= added_len;


	added_len	= add_secrets_to_circ(&fp->circ_bwd, message, len);
	if (added_len == -1)
		goto sec_err;

	fp->circ_fwd.index	= index_fwd;
	fp->circ_bwd.index	= index_bwd;
	fp->circ_fwd.id		= circ_id_fwd;
	fp->circ_bwd.id		= circ_id_bwd;
	fp->used		= 1;

	return 0;

no_fp:
	LOG("new mix FP, no slots left, circ_fwd = %i, circ_bwd = %i", circ_id_fwd, circ_id_bwd);
	goto destroy;
sec_err:
	LOG("new mix FP: error adding secrets circs %i/%i ", circ_id_fwd, circ_id_bwd);
	goto destroy;
size_err:
	LOG("new mix FP: buffer too small %i", len);
	goto destroy;

index_err:
	// we're not even reading the rest of the message at this point, so no circs to destroy.
	LOG("new mix FP: node index out of bounds.");
	return 2;

destroy:
	// FIXME: send destroy msg on circ_id_bwd & circ_id_fwd
	if (fp)
	{
		free_circ(&fp->circ_fwd);
		free_circ(&fp->circ_bwd);
	}

	return 1;
}

int
process_update_local_udp_dest(uint8_t *	message,
			      int	len)
{
	struct local_fp *		loc_fp		= NULL;
	struct circ *			circ		= NULL;
	int				circ_id;
	addr				peer;
	int				index;
	int				out;
	int				nb_secrets;
	int				i;
	int				circ_out_index	= 0;

	if (4 > len)
		goto size_err;
	index	= ntohl(*((uint32_t *) message));
	len	-= 4;
	message	+= 4;

	if (index < 0 || index >= MAX_FP_LOCAL_CIRCS)
		goto index_err;

	loc_fp	= &(state->local_fp[index]);

	if (4 > len)
		goto size_err;
	circ_id	= ntohl(*((uint32_t *) message));
	len	-= 4;
	message	+= 4;

	if (4 > len)
		goto size_err;
	out	= message[0];
	len	-= 1;
	message	+= 1;

	if (out) // 1 == out, 0 == in
	{
		if (4 > len)
			goto size_err;
		circ_out_index	= ntohl(*((uint32_t *) message));
		message		+= 4;
		len		-= 4;
		LOG("Updating local udp with %i as out circuit", circ_id);
		circ		= &loc_fp->circ_out;
	}
	else
	{
		uint8_t *	msg;

		msg	= parse_addr(message, len, &peer);
		if (!msg)
			goto baddata_err;

		len	-= msg - message;
		message = msg;
		if (4 > len)
			goto size_err;

		if (peer.ss.ss_family == AF_INET)
			peer.s4.sin_port	= htons(peer.s4.sin_port);
		else
			peer.s6.sin6_port	= htons(peer.s6.sin6_port);

		memcpy(&loc_fp->local_in_peer, &peer, sizeof (addr));
		LOG("Updating local udp with %i as in circuit", circ_id);
		circ	= &loc_fp->circ_in;
	}

	nb_secrets	= ntohl(*((uint32_t *) message));
	message		+= 4;
	len		-= 4;

	if (nb_secrets * HERD_SECRET_SIZE > len && nb_secrets <= MAX_NB_SECRETS)
		goto size_err;

	// wait until no more reasonable errors can occur to update data:
	circ->id		= circ_id;
	circ->nb_secrets	= nb_secrets;

	if (out)
		circ->index	= circ_out_index;

	for (i = 0; i < nb_secrets; ++i)
	{
		circ->secrets[i]	= malloc(HERD_SECRET_SIZE);
		if (!circ->secrets[i])
			goto this_is_the_end;
		memcpy(circ->secrets[i], message + i * HERD_SECRET_SIZE, HERD_SECRET_SIZE);
	}
	// FIXME : add_secrets_to_circ(circ, message, len);

	if (out && pthread_create(&loc_fp->write_tid, NULL, forward_to_circ, loc_fp) != 0)
		goto thread_err;

	return 0;

this_is_the_end:
	LOG("malloc failed, getting out of here.");
	exit(1);
thread_err:
	LOG("thread error: %s", strerror(errno));
	exit(1);
baddata_err:
	LOG("update local udp dest: unexpected data on index %i", index);
	return 4;
index_err:
	LOG("update local udp dest: connection index out of bounds %i", index);
	return 3;
size_err:
	LOG("update local udp dest: buffer too small %i", len);
	return 1;
}

int
process_open_local_udp(uint8_t *	message,
		       int		len)
{
	int			sock;
	struct sockaddr_in	local_addr;
	socklen_t		local_addr_len	= sizeof (struct sockaddr_in);
	struct local_fp *	local_fp	= NULL;
	int			index		= MAX_FP_LOCAL_CIRCS;
	int			cookie		= 0;


	if (4 > len)
		goto size_err;
	cookie	= ntohl(*((uint32_t *) message));
	LOG("got open local udp with %u cookie.", cookie);

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		goto socket_err;

	local_addr.sin_port	= 0;
	local_addr.sin_family	= AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &local_addr.sin_addr.s_addr);

	if (bind(sock, (struct sockaddr *) &local_addr, sizeof (struct sockaddr_in)) == -1)
		goto bind_err;

	if (getsockname(sock, (struct sockaddr *) &local_addr, &local_addr_len) == -1)
		goto getsock_err;

	for (int i = 0; i < MAX_FP_LOCAL_CIRCS && index == MAX_FP_LOCAL_CIRCS; ++i)
		if (state->local_fp[i].used == 0)
			index	= i;

	if (index == MAX_FP_LOCAL_CIRCS)
		goto all_used_err;

	local_fp	= &state->local_fp[index];
	local_fp->fd	= sock;
	local_fp->used	= 1;
	local_fp->port	= local_addr.sin_port;
	send_local_udp_ack(cookie, index, local_addr.sin_port);

	return 0;

size_err:
	LOG("Packet too small");
	return 3;
all_used_err:
	LOG("Hit max local sockets");
	return 3;
getsock_err:
	LOG("Error on getsockname local socket");
	return 3;
socket_err:
	LOG("Error opening local socket");
	return 2;
bind_err:
	LOG("Error binding local socket");
	return 1;
}

int
process_connect_to_node(uint8_t *	message,
			int	len)
{
	addr			peer;
	int			size;
	int			role;
	int			cookie = 0;
	uint8_t *		msg;
	uint8_t *		id;
	struct node_info *	node;
	int			node_i;
	char			print_addr[INET6_ADDRSTRLEN+1];

	if (4 > len)
		goto size_err;
	cookie	= ntohl(*((uint32_t *) message));
	message	+= 4;
	len	-= 4;
	LOG("got connect with %u cookie.", cookie);

	if (1 > len)
		goto size_err;
	role	= ntohl(*((uint32_t *) message));
	message	+= 1;
	len	-= 1;

	msg	= parse_addr(message, len, &peer);
	if (!msg)
		goto err;
	len	-= msg - message;
	size	= state->ntor_id_size;

	if (size > len)
		goto size_err;
	alloc_and_copy_string(msg, &id, size);

	node_i	= get_free_node(state);
	if (node_i == -1)
		goto node_err;
	node	= &state->nodes[node_i];

	node->ntor_id	= id;
	node->used	= 1;
	node->peer_addr	= peer;
	node->cookie	= cookie;
	node->role	= role;

	pthread_mutex_init(&node->ssl_lock, NULL);
	pthread_mutex_init(&node->herd_lock, NULL);

	if (pthread_create(&node->read_tid, NULL, start_client, node) != 0)
	{
		perror("pthread_create");
		exit(-1);
	}


	if (peer.ss.ss_family == AF_INET)
		LOG("Connected to %s:%i", inet_ntop(AF_INET, &peer.s4.sin_addr, print_addr, INET6_ADDRSTRLEN), peer.s4.sin_port);
	else
		LOG("Connected to %s:%i", inet_ntop(AF_INET6, &peer.s6.sin6_addr, print_addr, INET6_ADDRSTRLEN), peer.s6.sin6_port);
	fflush(log_file);

	return 0;

	int		ret;
node_err:
	LOG("Already have a connection to node or no more free nodes");
	ret	= 3;
	goto err;
size_err:
	LOG("given size longer than buffer, %i > %i", size, len);
	ret	= 2;
	goto err;
err:
	ret	= 1;
	if (cookie)
		send_ack(cookie, ret, 0);

	return ret;
}

int
process_rm_node(uint8_t *	message,
		int		len)
{
	int	index;

	if (4 > len)
		goto err_size;
	index	= ntohl(*((uint32_t *) message));

	free_node(index);

	return 0;

err_size:
	LOG("RM node, bad length = %i", len);
	return 1;
}

int
process_rm_local_udp(uint8_t *	message,
		     int	len)
{
	int			index;
	struct local_fp *	fp;

	if (4 > len)
		goto err_size;

	if (state->role != HERD_APP_PROXY)
		goto err_mix;

	index	= ntohl(*((uint32_t *) message));

	if (index > 0 || index >= MAX_FP_LOCAL_CIRCS)
		goto err_id;

	fp	= &state->local_fp[index];

	pthread_cancel(fp->write_tid);

	free_circ(&fp->circ_in);
	free_circ(&fp->circ_out);

	close(fp->fd);

	memset(fp, 0, sizeof (struct local_fp));

	return 0;

err_size:
	LOG("RM local UDP, bad length = %i", len);
	return 1;
err_id:
	LOG("RM local UDP, bad fp index = %i", index);
	return 2;
err_mix:
	LOG("RM local UDP makes no sense as mix");
	return 3;
}

int
process_rm_mix_fp(uint8_t *	message,
		  int		len)
{
	int			circ_fwd;
	struct mix_fp *		mfp	= 0;

	if (4 > len)
		goto err_size;

	// HERD_APP_PROXY ignores this msg. local_fp is freed by rm'ing corresponding local udp socket
	if (state->role == HERD_APP_PROXY)
		return 0;

	circ_fwd	= ntohl(*((uint32_t *) message));
	for (int i = 0; i < MAX_FP_MIX_CIRCS && !mfp; ++i)
		if (state->mix_fp[i].circ_fwd.id == circ_fwd)
			mfp	= &state->mix_fp[i];

	if (!mfp)
		goto err_circ;

	free_circ(&mfp->circ_fwd);
	free_circ(&mfp->circ_bwd);
	memset(mfp, 0, sizeof (struct mix_fp));

	return 0;

err_size:
	LOG("RM FP, bad length = %i", len);
	return 1;
err_circ:
	LOG("RM FP, bad fp circ_in = %i", circ_fwd);
	return 3;
}

int
process_update_node_secret(uint8_t *	message,
			   int		len)
{
	int			index;
	struct node_info *	node;
	uint8_t *		secret;

	if (4 > len)
		goto err_size;
	index	= ntohl(*(uint32_t*) &message[0]);
	message	+= 4;
	len	+= 4;

	if (HERD_SECRET_SIZE > len)
		goto err_size;

	secret	= malloc(HERD_SECRET_SIZE);
	memcpy(secret, message, HERD_SECRET_SIZE);

	if (state->role == HERD_APP_PROXY)
	{
		if (index < 0 || index >= MAX_NODES)
			goto index_err;

		node		= &state->nodes[index];
		node->secret	= secret;
		LOG("Added MIX shared secret to %i", index);
	}
	else if (state->role == HERD_MIX)
	{
		if (index < 0 || index >= MAX_CH_CLIENTS)
			goto index_err;

		state->channel.client_secrets[index]	= secret; // FIXME hardcoded to one channel for now
		LOG("Added APP-PROXY shared secret to %i", index);
	}
	else
		goto role_err;

	return 0;

role_err:
	free(secret);
	LOG("update node secret makes no sense with role: %i", state->role);
	return 2;
index_err:
	free(secret);
	LOG("update node secret: index out of bounds %i", index);
	return 2;
err_size:
	LOG("update node secret, bad length = %i", len);
	return 1;
}

int
process_update_role(uint8_t *	message,
		    int		len)
{
	int			role;
	int			index;

	if (5 > len)
		goto err_size;

	role	= message[0];
	index	= ntohl(*(uint32_t*) &message[1]);


	if (index < 0 || index >= MAX_NODES)
		goto index_err;

	state->nodes[index].role	= role;

	LOG("update role, index %i == %i", index, role);

	return 0;

index_err:
	LOG("update role: index out of bounds %i", index);
	return 2;
err_size:
	LOG("update role, bad length = %i", len);
	return 1;
}

int
process_forward(uint8_t *	message,
		int		len)
{
	int			node_i = -1;

	if (4 > len)
		goto err_size;
	node_i	= ntohl(*((uint32_t *) message));
	message	+= 4;
	len	-= 4;

	if (node_i < 0 || node_i >= MAX_NODES)
		goto index_err;

	struct node_info *	node	= &state->nodes[node_i];

	LOG("bool: %i %i %p", state->role == HERD_APP_PROXY, node->role == HERD_SP, node->secret);
	LOG("val: %i %i %p", state->role, node->role, node->secret);
	if (state->role == HERD_APP_PROXY && node->role == HERD_SP && node->secret)
		return send_cell_to_sp(message, node->secret, 1, node_i);

	return add_to_queue(node_i, message, len);

index_err:
	LOG("update role: index out of bounds %i", node_i);
	return 2;
err_size:
	LOG("herd node id %i was asked to send a packet with bad length = %i", node_i, len);
	return 1;
}

int
process_herd_message(uint8_t *	message,
		     int	len,
		     int	herd_socket,
		     addr *	herd_peer,
		     socklen_t	herd_peer_len)
{
	uint8_t		cmd	= message[0];

	++message;
	--len;

	if (cmd == HERD_CMD_INIT)
	{
		if (process_init(message, len))
			goto cmd_err;
		else
		{
			state->herd_socket	= herd_socket;
			state->herd_peer	= *herd_peer;
			state->herd_peer_len	= herd_peer_len;

			return 0;
		}
	}

	if (!state)
		goto state_err;

	switch (cmd)
	{
		case HERD_CMD_CONNECT_TO_NODE:
			process_connect_to_node(message, len);
			break;
		case HERD_CMD_OPEN_LOCAL_UDP:
			process_open_local_udp(message, len);
			break;
		case HERD_CMD_UPDATE_LOCAL_UDP_DEST:
			process_update_local_udp_dest(message, len);
			break;
		case HERD_CMD_NEW_MIX_FP:
			process_new_mix_fp(message, len);
		case HERD_CMD_FORWARD:
			process_forward(message, len);
			break;
		case HERD_CMD_RM_NODE:
			process_rm_node(message, len);
			break;
		case HERD_CMD_RM_LOCAL_UDP:
			process_rm_local_udp(message, len);
			break;
		case HERD_CMD_RM_MIX_FP:
			process_rm_mix_fp(message, len);
			break;
		case HERD_CMD_UPDATE_ROLE:
			process_update_role(message, len);
			break;
		case HERD_CMD_UPDATE_NODE_SECRET:
			process_update_node_secret(message, len);
			break;
		case HERD_CMD_PING:
			process_ping(message, len);
			break;
		case HERD_CMD_DATA:
			// goto err_should never happen.
		case HERD_CMD_NEW_CIRCUIT:
		default:
			LOG("Unsupported message type: %i", cmd);
			return 2;
	}

	return 0;
state_err:
	LOG("Ignoring command %i, we are uninitialized", cmd);
	return 1;
cmd_err:
	LOG("Ignoring command %i, error processing it", cmd);
	return 2;
}

int
test_forward_to_circ(uint8_t *	in,
		     uint8_t *  out_final,
		     struct circ * circ_out,
		     int	len)
{
	uint8_t			buffer[HERD_PACKET_SIZE];
	uint8_t			read_buffer[AQ_BUFFER_MAX]; // FIXME: this should be buffer - header sizes.
	//uint8_t *		out;
	//FD_ZERO(&read_fds);
	//FD_SET(herd_socket, &read_fds);

	int	read_len	= len;

	if (read_len < 0)
		goto read_err;
	if (read_len == (AQ_BUFFER_MAX - 1))
		LOG("WARNING: buffer totally filled %i", read_len);
	if (read_len < 0)
		goto read_err;
	if (read_len == 0)
		goto zero_fail;

	*(uint32_t *) buffer		= htonl(read_len + 9 + HERD_IV_SIZE + 11);	// FIXME header sizes.
	*(uint32_t *) &buffer[4]	= htonl(circ_out->id);
	buffer[8]			= 3;					//relay
	RAND_bytes(buffer + 9, HERD_IV_SIZE);

	uint8_t	*	iv		= buffer + 9;
	uint8_t	*	stream		= buffer + 25;

	stream[0]			= 2;					// relay data
	*(uint16_t *) &stream[1]	= htons(0);				// recognized
	*(uint16_t *) &stream[3]	= htons(101);				// stream id
	*(uint32_t *) &stream[5]	= htonl(101);				// digest
	*(uint16_t *) &stream[9]	= htons(read_len);			// size

	if (read_len > AQ_BUFFER_MAX - 11 - 20) // 11 = stream, 20 = circ
		goto too_big_fail;

	memcpy(stream + 11, in, read_len);
	uint8_t *	inn		= stream;
	uint8_t *	out		= read_buffer;

	if (!(out = toggle_onion_skins(inn, out, circ_out, iv, read_len + 11, ENCRYPT))) // FIXME will replace read_len with HERD_PACKET_SIZE, this is tmp.// FIXME: also, encrypt whole packet len with padding, not just the user payload.
		goto enc_fail;

	memcpy(stream, out, read_len + 11);

	LOG("Added %i", read_len + 11);
	LOG("msg fin  %i %i %i %i ", stream[0], stream[1], stream[2], stream[3]);
	memcpy(out_final, buffer, HERD_PACKET_SIZE);
	//add_to_queue(fp->circ_out.index, buffer, HERD_PACKET_SIZE);

	return 0;

zero_fail:
	LOG("read zero, this shouldn't happen.");
enc_fail:
	LOG("encryption failed, dropping.");
too_big_fail:
	LOG("received a too big packet, dropping.");

read_err:
	// FIXME: add cleanup. memset 0 where needed.
	LOG("recvfrom: %s", strerror(errno));
	return 9; // just to remove the warning
}

int
test_process_fastpath(uint8_t *			message,
		      int			len,
		      struct circ *		circ_in,
		      uint8_t *			out_final)
{
	// for app-proxy only. we'll see about mixes later.
	// Takes a packet received from dtls, removes encryption & cell headers, forwards to local udp socket.
	int			circ;
	int			actual_len	= 0;
	int			initial_len	= len;
	int			cmd;
	uint8_t *		relay_cell;
	int			err		= 0;
	uint8_t			in[AQ_BUFFER_MAX];
	uint8_t			buffer[AQ_BUFFER_MAX];
	uint8_t *		out		= buffer;
	uint8_t *		iv;

	if (4 > len)
		goto size_err;

	actual_len	= ntohl(*((uint32_t *) message));

	if (len < actual_len) // FIXME, not sure yet.
		goto size_err;

	circ		= ntohl(*((uint32_t *) (message + 4)));
	cmd		= message[8];
	if (cmd == 0)
		goto padding;
	if (cmd != 3) // relay == 3
		goto not_relay;
	// else look for mix fp, checking circ_[in|out].id & matching node->fd to circ_xx.fd

	iv		= message + 9;
	relay_cell	= iv + HERD_IV_SIZE;
	len		= actual_len - 9 - HERD_IV_SIZE;
	LOG("init_len; %i, actual_len %i, len: %i", initial_len, actual_len, len);

	LOG("%i %i %i %i", message[20 + 0], message[20 + 1], message[20 + 2], message[20 + 3]);
	LOG("%ld, %i", (&message[20 + 0]) - relay_cell, HERD_IV_SIZE);
	memcpy(in, relay_cell, len);

	if (!(out = toggle_onion_skins(in, out, circ_in, iv, len, DECRYPT)))
		goto evp_err;

	// the place holder for digest:
	for (int i = 0; i <= 9; ++i)
		LOG("%i:	%i	%i	%i", i, out[i], ntohs(*(uint16_t *)&out[i]), ntohl(*(uint32_t *)&out[i]));
	if (101 != ntohs(*(uint16_t *) &out[3]) || 101 != ntohl(*(uint32_t *) &out[5]) || ntohs(*(uint16_t *) &out[1]))
		goto not_recognized;

	if (out[0] != 2)
		goto not_relay_data;

	actual_len	= ntohs(*(uint16_t *) &out[9]);

	out		+= 11; // we don't need that header anymore

	if (actual_len > len - 11)
		goto actual_len_err;

	memcpy(out_final, out, actual_len);
	//actual_len	= sendto(fp->fd, out, actual_len, 0, (struct sockaddr * restrict) &fp->local_in_peer, sizeof (addr));

	return 0;

padding:
	LOG("Fastpath: circ = %i: dropping padding.", circ);
	return 4;
actual_len_err:
	LOG("Fastpath, circ = %i, bad len: givenlen = %i, maxlen = %i, len = %i", circ, actual_len, len - 11 - 2, len);
	err	= 1;
	goto forward;
size_err:
	LOG("Fastpath, size error, forwarding to herd. len = %i, alen = %i", len, actual_len); // or drop? attacker could intentionally set wrong sizes to see it go through herd for some reason?
	err	= 2;
	goto forward;
evp_err:
	LOG("Fastpath, circ = %i, failed to decrypt", circ);
	err	= 3;
	goto forward;
not_relay_data:
	LOG("Fastpath, not a relay data cmd, circ = %i, cmd = %i", circ, out[0]);
	goto forward;
not_recognized:
	LOG("Fastpath, not recognized, circ = %i", circ);
	goto forward;
not_relay:
	LOG("Fastpath, not a relay packet");
forward:
	//send_data_packet(message, initial_len, node);
	return err;
}

void test()
{
	// 1 Parsing:
//	addr		peer;
//	uint8_t		msgip[128];
//	uint8_t		msgip6[128];
//	uint8_t *	m;
//
//	memcpy(msgip, "u:123.0.30.4:12345\000lolol", 25);
//	memcpy(msgip6, "u:[FE80:0:1:2::3]:12345\000lolol", 29);
//
//
//	m = parse_addr(msgip, 0, &peer);
//	LOG("rest4:%s", m);
//	m = parse_addr(msgip6, 0, &peer);
//	LOG("rest6:%s", m);


	// 2 fp
////	struct circ	c;
//	struct circ	c2;
//	uint8_t		orig[AQ_BUFFER_MAX];
//	uint8_t		in[AQ_BUFFER_MAX];
//	uint8_t		out[AQ_BUFFER_MAX];
//	uint8_t		iv[16];
//	uint8_t *	end;
//	int		nbsec = 1;
//
//	state	= calloc(1, sizeof (struct state));
//	state->cipher	= EVP_get_cipherbyname("aes-256-ctr");
//
//	for (int i = 0; i < nbsec; ++i)
//	{
//		c.id = 10213;
//		c2.id = 10213;
//		c.secrets[i] = malloc(HERD_SECRET_SIZE);
//		c2.secrets[nbsec - 1 - i] = malloc(HERD_SECRET_SIZE);
//		RAND_bytes(c.secrets[i], HERD_SECRET_SIZE);
//		memcpy(c2.secrets[nbsec - 1 - i], c.secrets[i], HERD_SECRET_SIZE);
//	}
//	c.nb_secrets = nbsec;
//	c2.nb_secrets = nbsec;
//
//	RAND_bytes(iv, 16);
//	RAND_bytes(orig, 128);
//
//	memcpy(in, orig, 128);
//	end = toggle_onion_skins(in, out, &c, iv, 128, ENCRYPT);
//	end = toggle_onion_skins(end, in, &c2, iv, 128, DECRYPT);
//
//	LOG("%i %i %i %i", end[0], orig[0], end[1], orig[1]);
//	if (!memcmp(end, orig, 128))
//		LOG("toggle_onion_skins works");
//	else
//		LOG("toggle_onion_skin broken");
//
//
//	test_forward_to_circ(end, out, &c, 128);
//	LOG("test_forward_to_circ out: %i %i %i %i ---------", out[0 + 20], out[1 + 20], out[2 + 20], out[3 + 20]);
//	memset(in, 0, 128);
//	test_process_fastpath(out, AQ_BUFFER_MAX, &c, in);
//
//	if (!memcmp(in, orig, 128))
//		LOG("fp works");
//	else
//		LOG("fp broken");

	state	= calloc(1, sizeof (struct state));
	state->cipher	= EVP_get_cipherbyname("aes-256-ctr");

	EVP_CIPHER_CTX			ctx;

	uint32_t	orig;
	uint8_t		iv[16];
	uint8_t		key[32];
	char		err[256];


	RAND_bytes(iv, 16);
	RAND_bytes(key, 16);
	RAND_bytes((uint8_t *)&orig, 4);

	uint8_t				out[HERD_PACKET_SIZE * 2];
	uint8_t				in[HERD_PACKET_SIZE * 2];
	int				outlen = 0;

	// 1 check header's msg type first:
	memcpy(in, &orig, 4);

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	if (!EVP_CipherInit_ex(&ctx, state->cipher, NULL, key, iv, ENCRYPT))
		goto err;

	if (!EVP_CipherUpdate(&ctx, out, &outlen, in, 4))
		goto err;

	printf("outlen 1 %i\n", outlen);

	if (!EVP_CipherFinal_ex(&ctx, out + outlen, &outlen))
		goto err;

	printf("res %u %u\n", orig, *(uint32_t*) out);
	printf("outlen 2 %i\n", outlen);
	// lol
	memcpy(in, out, 4);

	if (!EVP_CipherInit_ex(&ctx, state->cipher, NULL, key, iv, DECRYPT))
		goto err;

	if (!EVP_CipherUpdate(&ctx, out, &outlen, in, 4))
		goto err;

	printf("outlen 1 %i\n", outlen);

	if (!EVP_CipherFinal_ex(&ctx, out + outlen, &outlen))
		goto err;

	printf("res %u %u\n", orig, *(uint32_t*) out);

	struct node_info *	node = state->nodes;
	memset(node, 0, 4 * sizeof (struct node_info));

	struct channel *	channel = &state->channel;

	for (int i = 0; i < 3; ++i)
	{
		channel->client_secrets[i]	= malloc(HERD_SECRET_SIZE);
		RAND_bytes(channel->client_secrets[i], HERD_SECRET_SIZE);
		node[i].used	= 1;
		node[i].role	= HERD_SP;
	}
	node[3].used	= 1;

	// client side: (3 of them)
	send_cell_to_sp(NULL, channel->client_secrets[0], 0, 0);
	send_cell_to_sp(NULL, channel->client_secrets[1], 0, 1);

	memset(in, 0, HERD_PACKET_SIZE * 2);
	memset(in, 'D', HERD_PACKET_SIZE * 2);
	memset(in + HERD_PACKET_SIZE - 2, 'B', HERD_PACKET_SIZE);
	memcpy(in, "lol", 3);
	//in[HERD_PACKET_SIZE + 2] = 0;
	send_cell_to_sp(in, channel->client_secrets[2], 1, 2);

	for (int i = 0; i < 3; ++i)
		xor_to_queue(&node[3], i, node[i].queue[0]);

	mix_unxor(node[3].queue[0], HERD_PACKET_SIZE + sizeof (struct sp_manifest_header), channel);
	printf("%lu --- %s\n",  strlen((char*)node[3].queue[0] + sizeof (struct sp_manifest_header)), node[3].queue[0] + sizeof (struct sp_manifest_header));
	printf("%lu\n", sizeof (int));

//	RAND_bytes((uint8_t *)&h->seq, 4);
//	RAND_bytes((uint8_t *)&h->iv, 16);
//	printf("header -- seq: %i -- iv: %i %i %i %i\n", h->seq, h->iv[0], h->iv[1], h->iv[14], h->iv[15]);
//	//int tmp = ntohl(h->seq);
//	memcpy(in + sizeof (struct sp_client_header), &h->seq, 4);
//	toggle_onion_skin(in + sizeof (struct sp_client_header), out, circs[0].secrets[0], h->iv, HERD_PACKET_SIZE, ENCRYPT);
//	printf("msg -- iv: %i %i %i %i\n", out[0], out[1], out[14], out[15]);
//	memcpy(in + sizeof (struct sp_client_header), out, HERD_PACKET_SIZE);
//	toggle_onion_skin((uint8_t *) &h->msg_type, out, circs[0].secrets[0], h->iv, 4, ENCRYPT);
//	printf("msg type: %i %i\n", h->msg_type, *(uint32_t *)out);
//	memcpy(&h->msg_type, out, 4);
//	xor_to_queue(node, 0, in);
//
//	// pkt 2
//	memset(in, 0, HERD_PACKET_SIZE * 2);
//
//	RAND_bytes((uint8_t *)&h->seq, 4);
//	RAND_bytes((uint8_t *)&h->iv, 16);
//	printf("header -- seq: %i -- iv: %i %i %i %i\n", h->seq, h->iv[0], h->iv[1], h->iv[14], h->iv[15]);
//	//tmp = ntohl(h->seq);
//	memcpy(in + sizeof (struct sp_client_header), &h->seq, 4);
//	toggle_onion_skin(in + sizeof (struct sp_client_header), out, circs[1].secrets[0], h->iv, HERD_PACKET_SIZE, ENCRYPT);
//	printf("msg -- iv: %i %i %i %i\n", out[0], out[1], out[14], out[15]);
//	memcpy(in + sizeof (struct sp_client_header), out, HERD_PACKET_SIZE);
//	toggle_onion_skin((uint8_t *) &h->msg_type, out, circs[1].secrets[0], h->iv, 4, ENCRYPT);
//	printf("msg type: %i %i\n", h->msg_type, *(uint32_t *)out);
//	memcpy(&h->msg_type, out, 4);
//	xor_to_queue(node, 1, in);
//
//	// pkt 3
//	memset(in, 0, HERD_PACKET_SIZE * 2);
//
//	RAND_bytes((uint8_t *)&h->seq, 4);
//	RAND_bytes((uint8_t *)&h->iv, 16);
//	printf("header -- seq: %i -- iv: %i %i %i %i\n", h->seq, h->iv[0], h->iv[1], h->iv[14], h->iv[15]);
//
//	toggle_onion_skin(in + sizeof (struct sp_client_header), out, circs[2].secrets[0], h->iv, HERD_PACKET_SIZE, ENCRYPT);
//	memcpy(in + sizeof (struct sp_client_header), out, HERD_PACKET_SIZE);
//	printf("msg -- iv: %i %i %i %i\n", out[0], out[1], out[14], out[15]);
//	h->msg_type = htonl(1);
//	toggle_onion_skin((uint8_t *) &h->msg_type, out, circs[2].secrets[0], h->iv, 4, ENCRYPT);
//	printf("msg type: %i %i\n", h->msg_type, *(uint32_t *)out);
//	memcpy(&h->msg_type, out, 4);
//	xor_to_queue(node, 2, in);
//
//	struct sp_manifest_header * all = (struct sp_manifest_header *) node->queue[0];
//	for (int j = 0; j < 3; ++j)
//		printf("header %i -- seq: %i -- iv: %i %i %i %i\n", j, all->client[j].seq, all->client[j].iv[0], all->client[j].iv[1], all->client[j].iv[14], all->client[j].iv[15]);
//

err:
	ERR_error_string_n(ERR_get_error(), err, 256);
	LOG("EVP error: %s", err);
}

int
main(int	argc,
     char **	argv)
{
	int			port;
	int			herd_socket;
	struct sockaddr_in	local_addr;
	fd_set			read_fds;
	uint8_t			herd_buffer[AQ_BUFFER_MAX];

	log_file	= fopen("dtls-handler.log", "a+");
	//log_file	= stdout; // FIXME, for debugging.
	pthread_mutex_init(&log_lock, NULL);

	OpenSSL_add_all_algorithms();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	// test();
	// exit(1);

	if (!log_file)
	{
		printf("could not open log file");
		goto error;
	}

	if (argc == 1)
	{
		LOG("no port given");
		goto error;
	}

	port = strtol(argv[1], 0, 10);
	LOG("Using port: %i for herd communication", port);
	fflush(log_file);

	herd_socket = socket(AF_INET, SOCK_DGRAM, 0);

	if (herd_socket == -1)
	{
		LOG("Error opening herd socket");
		goto error;
	}

	local_addr.sin_port	= htons(port);
	local_addr.sin_family	= AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &local_addr.sin_addr.s_addr);

	if (bind(herd_socket, (struct sockaddr *) &local_addr, sizeof (struct sockaddr_in)) == -1)
	{
		LOG("Error binding herd socket");
		goto error;
	}

	FD_ZERO(&read_fds);
	FD_SET(herd_socket, &read_fds);

	while (1)
	{
		addr		peer;

		socklen_t	addrlen	= sizeof (peer);

		int read_len	= recvfrom(herd_socket, herd_buffer, AQ_BUFFER_MAX, MSG_WAITALL, (struct sockaddr * restrict) &peer, &addrlen);

		if (read_len < 0)
			goto recv_error;

		if (read_len == AQ_BUFFER_MAX)
			LOG("WARNING: herd_buffer totally filled %i", read_len);

		process_herd_message(herd_buffer, read_len, herd_socket, &peer, addrlen);

		if (read_len < 0)
			goto send_error;
	}


	fclose(log_file);
	return 0;
recv_error:
	LOG("recvfrom: %s", strerror(errno));
	goto error;
send_error:
	LOG("sendto: %s", strerror(errno));
error:
	fclose(log_file);
	return 1;
}
