#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "const.h"
#include "ev.h"

#define NUM_BACKLOG 4096
#define BUFSIZE 4096

/*
 * Sock
 */

ssize_t sock_read(int fd, void *buf, size_t len) {
  ssize_t n;

eintr:
  n = read(fd, buf, len);

  if (n == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return RES_AGAIN;
    } else if (errno == EINTR) {
      goto eintr;
    } else {
      return RES_ERR;
    }
  } else if (n == 0) {
    return RES_CLOSED;
  }

  return n;
}

ssize_t sock_write(int fd, void *buf, size_t len) {
  ssize_t n;

eintr:
  n = write(fd, buf, len);

  if (n == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return RES_AGAIN;
    } else if (errno == EINTR) {
      goto eintr;
    } else {
      return RES_ERR;
    }
  }

  return n;
}

/*
 * Connection primitives
 */

#define CONN_READ_CLOSED (1 << 1)
#define CONN_READABLE (1 << 2)
#define CONN_WRITABLE (1 << 3)

struct conn_t {
  struct ev_sock_t sock;
  char *buf;
  int size;
  int state;
};

struct conn_t *create_conn(int fd) {
  struct conn_t *new_conn = malloc(sizeof(struct conn_t));
  if (new_conn == NULL) {
    return NULL;
  }
  new_conn->buf = malloc(BUFSIZE);
  if (new_conn->buf == NULL) {
    free(new_conn);
    return NULL;
  }
  int res = ev_init_sock(&(new_conn->sock), fd, new_conn);
  if (res != RES_OK) {
    free(new_conn);
    return NULL;
  }
  new_conn->size = 0;
  new_conn->state = CONN_READABLE | CONN_WRITABLE;
  return new_conn;
}

// TODO: must check read or write (other) event is cached
void delete_conn(struct conn_t *conn) {
  close(conn->sock.fd);
  free(conn->buf);
  free(conn);
}

/*
 * Handlers
 */

int handler(struct conn_t *conn) {
  int changed = 0;
  ssize_t res;

  while (conn->state & (CONN_READABLE | CONN_WRITABLE)) {
    // read
    if ((conn->state & CONN_READABLE) && conn->size < BUFSIZE) {
      res = sock_read(conn->sock.fd, conn->buf + conn->size,
                      BUFSIZE - conn->size);
      if (res == RES_ERR) {
        perror("read");
        return RES_ERR;
      } else if (res == RES_CLOSED) {
        if (conn->size == 0) {
          return RES_CLOSED;
        }
        conn->state &= ~CONN_READABLE;
        conn->state |= CONN_READ_CLOSED;
      } else if (res == RES_AGAIN) {
        conn->state &= ~CONN_READABLE;
        changed |= CONN_READABLE;
      } else {
        conn->size += res;
      }
    } else if ((conn->state & CONN_WRITABLE) == 0) {
      // readable but buffer is full and not writable
      break;
    }

    // write
    if ((conn->state & CONN_WRITABLE) && conn->size > 0) {
      res = sock_write(conn->sock.fd, conn->buf, conn->size);
      if (res == RES_ERR) {
        perror("write");
        return RES_ERR;
      } else if (res == RES_AGAIN) {
        conn->state &= ~CONN_WRITABLE;
        changed |= CONN_WRITABLE;
      } else {
        ssize_t offset = conn->size;
        conn->size -= res;
        if (conn->size > 0) {
          memmove(conn->buf, conn->buf + offset, conn->size);
          conn->state &= ~CONN_WRITABLE;
          changed |= CONN_WRITABLE;
        }
      }
    } else if ((conn->state & CONN_READABLE) == 0) {
      // writable but buffer is empty and not readable
      break;
    }

    // check closed
    if (conn->size == 0 && conn->state & CONN_READ_CLOSED) {
      return RES_CLOSED;
    }
  }
  return changed;
}

void handle_write(struct ev_loop_t *loop, struct ev_sock_t *sock, void *data);

void handle_read(struct ev_loop_t *loop, struct ev_sock_t *sock, void *data) {
  int res;
  struct conn_t *conn = data;
  conn->state |= CONN_READABLE;

  int changed = handler(conn);
  if (changed < 0) {
    delete_conn(conn);
  } else {
    if (changed & CONN_WRITABLE) {
      res = ev_register_write(loop, sock, handle_write);
      if (res != RES_OK) {
        delete_conn(conn);
      }
    }
    if (conn->state & CONN_READABLE) {
      res = ev_unregister_read(loop, sock);
      if (res != RES_OK) {
        delete_conn(conn);
      }
    }
  }
}

void handle_write(struct ev_loop_t *loop, struct ev_sock_t *sock, void *data) {
  int res;
  struct conn_t *conn = data;
  conn->state |= CONN_WRITABLE;

  int changed = handler(conn);
  if (changed < 0) {
    delete_conn(conn);
  } else {
    if (changed & CONN_READABLE) {
      res = ev_register_read(loop, sock, handle_read);
      if (res != RES_OK) {
        delete_conn(conn);
      }
    }
    if (conn->state & CONN_WRITABLE) {
      res = ev_unregister_write(loop, sock);
      if (res != RES_OK) {
        delete_conn(conn);
      }
    }
  }
}

void handle_accept(struct ev_loop_t *loop, struct ev_sock_t *sock, void *data) {
  int res;
  while (1) {
    int fd = accept(sock->fd, NULL, NULL);
    if (fd == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      } else if (errno == EINTR) {
        continue;
      }
      perror("accept");
      // TODO: send error signal
      abort();
    }

    fprintf(stderr, "accept sock : %d\n", fd);

    struct conn_t *conn = create_conn(fd);
    if (conn == NULL) {
#define MALLOC_CONN_ERROR_MSG "failed to allocate memory for connection\n"
      write(fd, MALLOC_CONN_ERROR_MSG, sizeof(MALLOC_CONN_ERROR_MSG));
      fprintf(stderr, MALLOC_CONN_ERROR_MSG);
      close(fd);
      continue;
    }

    int changed = handler(conn);
    if (changed < 0) {
      delete_conn(conn);
    } else {
      if (changed & CONN_READABLE) {
        res = ev_register_read(loop, &(conn->sock), handle_read);
        if (res != RES_OK) {
          delete_conn(conn);
        }
      }
      if (changed & CONN_WRITABLE) {
        res = ev_register_write(loop, &(conn->sock), handle_write);
        if (res != RES_OK) {
          delete_conn(conn);
        }
      }
    }
  }
}

int main(int argc, char const *argv[]) {
  printf("Hello World\n");

  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    perror("signal(SIGPIPE, SIG_IGN)");
    return 1;
  }

  char *laddrstr = "0.0.0.0";
  int res;
  struct sockaddr_in laddr;
  laddr.sin_family = AF_INET;
  laddr.sin_port = htons(3004);
  if ((res = inet_pton(AF_INET, laddrstr, &laddr.sin_addr)) <= 0) {
    if (res == 0) {
      fprintf(stderr, "invalid format for ipv4\n");
    } else {
      perror("inet_pton");
    }
    return 1;
  }

  int listenerfd;
  if ((listenerfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    return 1;
  }

  struct ev_sock_t listener;
  res = ev_init_sock(&listener, listenerfd, NULL);

  fprintf(stderr, "listener : %d\n", listener.fd);

  if (bind(listenerfd, (struct sockaddr *)&laddr, sizeof(laddr)) != 0) {
    perror("bind");
    return 1;
  } else if (listen(listenerfd, NUM_BACKLOG) != 0) {
    perror("listen");
    return 1;
  }

  struct ev_loop_t *loop = ev_create_loop();

  res = ev_register_read(loop, &listener, handle_accept);
  if (res != RES_OK) {
    return 1;
  }

  while (1) {
    res = ev_run_loop(loop);
    if (res != RES_OK) {
      perror("ev_run_loop");
      break;
    }
  }

  close(listenerfd);

  return 0;
}
