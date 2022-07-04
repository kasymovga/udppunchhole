#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#define debug(...) fprintf(stderr, __VA_ARGS__)
#define BUFLEN 2047

struct server {
	struct sockaddr_in addr;
	int port;
	time_t time;
	struct server *next;
};

struct server *server_list;

struct server *server_add(struct sockaddr_in *addr) {
	struct server *server = malloc(sizeof(struct server));
	if (!server) {
		perror("server_add:malloc");
		return NULL;
	}
	memcpy(&server->addr, addr, sizeof(struct sockaddr_in));
	server->next = server_list;
	server_list = server;
	return server;
}

struct server *server_find(struct sockaddr_in *addr) {
	for (struct server *server = server_list; server; server = server->next)
		if (!memcmp(&server->addr, addr, sizeof(struct sockaddr_in)))
			return server;

	return NULL;
}

void server_list_clean() {
	time_t _time = time(NULL);
	struct server *delete;
	for (struct server **inderect = &server_list; *inderect;) {
		if (_time - (*inderect)->time > 120) {
			delete = *inderect;
			debug("deleted server: %s:%i\n", inet_ntoa(delete->addr.sin_addr), (int)ntohs(delete->addr.sin_port));
			*inderect = (*inderect)->next;
			free(delete);
		} else
			inderect = &((*inderect)->next);
	}
}

void server_update(struct sockaddr_in *addr) {
	struct server *server;
	server = server_find(addr);
	if (!server) {
		debug("added new server: %s:%i\n", inet_ntoa(addr->sin_addr), (int)ntohs(addr->sin_port));
		server = server_add(addr);
	} else {
		debug("updated server: %s:%i\n", inet_ntoa(addr->sin_addr), (int)ntohs(addr->sin_port));
	}
	if (server) {
		server->time = time(NULL);
	}
	server_list_clean();
}

void server_list_punch_hole(int sock, struct sockaddr_in *addr) {
	char buf[1024];
	server_list_clean();
	int buf_len;
	for (struct server *server = server_list; server; server = server->next) {
		debug("sending request to %s:%i\n", inet_ntoa(server->addr.sin_addr), (int)ntohs(server->addr.sin_port));
		buf_len = snprintf(buf, 1024, "\377\377\377\377extResponse udppunchhole request %s:%i", inet_ntoa(addr->sin_addr), (int)ntohs(addr->sin_port));
		sendto(sock, buf, buf_len, 0, &server->addr, sizeof(server->addr));
		debug("sending request to %s:%i\n", inet_ntoa(addr->sin_addr), (int)ntohs(addr->sin_port));
		buf_len = snprintf(buf, 1024, "\377\377\377\377extResponse udppunchhole request %s:%i", inet_ntoa(server->addr.sin_addr), (int)ntohs(server->addr.sin_port));
		sendto(sock, buf, buf_len, 0, addr, sizeof(*addr));
	}
}

int main(int argc, char **argv) {
	struct sockaddr_in si_me, si_other;
	socklen_t slen;
	ssize_t recv_len;
	int testsock = -1;
	struct pollfd fds[1];
	fds[0].fd = -1;
	memset(&si_me, 0, sizeof(si_me));
	char buf[BUFLEN + 1];
	if ((fds[0].fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		goto finish;

	if ((testsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		goto finish;

	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(27950);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(fds[0].fd, (struct sockaddr*)&si_me, sizeof(si_me)) == -1)
		goto finish;

	for(;;) {
		fds[0].revents = 0;
		fds[0].events = POLLIN;
		if (poll(fds, 1, 2000) < 0)
			goto finish;

		if (fds[0].revents & POLLIN) {
			slen = sizeof(si_other);
			if ((recv_len = recvfrom(fds[0].fd, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) < 0)
				goto finish;

			buf[recv_len] = '\0';
			if (memcmp(buf, "\377\377\377\377extResponse udppunchhole serverkeepalive", 44) == 0) {
				debug("server keepalive from: %s:%i\n", inet_ntoa(si_other.sin_addr), (int)ntohs(si_other.sin_port));
				sendto(fds[0].fd, "\377\377\377\377extResponse udppunchhole pong", 33, 0, (struct sockaddr *)&si_other, sizeof(si_other));
				server_update(&si_other);
				//Server
			} else if (memcmp(buf, "\377\377\377\377extResponse udppunchhole request", 36) == 0) {
				server_list_punch_hole(fds[0].fd, &si_other);
			} else if (memcmp(buf, "\377\377\377\377extResponse udppunchhole porttest", 37) == 0) {
				debug("port test requested from %s:%i\n", inet_ntoa(si_other.sin_addr), (int)ntohs(si_other.sin_port));
				snprintf(buf, BUFLEN, "\377\377\377\377extResponse udppunchhole porttest %s", inet_ntoa(si_other.sin_addr));
				sendto(testsock, buf, strlen(buf), 0, (struct sockaddr *)&si_other, sizeof(si_other));
			} else {
				debug("unknown packet from %s:%i\n", inet_ntoa(si_other.sin_addr), (int)ntohs(si_other.sin_port));
				debug("packet=\n===\n%s\n===\n", buf);
				server_list_punch_hole(fds[0].fd, &si_other);
			}
		}
	}
finish:
	if (errno)
		perror("udppunchhole");

	if (fds[0].fd >= 0)
		close(fds[0].fd);
}
