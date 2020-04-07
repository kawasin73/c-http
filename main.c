#include <arpa/inet.h>
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
#include <assert.h>

// kqueue
#include <sys/event.h>

#define NUM_BACKLOG 4096
#define BUFSIZE 4096

#define TYPE_LISTENER 0
#define TYPE_CONN 1

/*
 * Connection primitives
 */

struct conn_t {
  int type;
  int fd;
  char *buf;
  int size;
  int eof;
};

struct conn_t *create_conn(int sock) {
  struct conn_t *new_conn = malloc(sizeof(struct conn_t));
  if (new_conn == NULL) {
    return NULL;
  }
  new_conn->buf = malloc(BUFSIZE);
  if (new_conn->buf == NULL) {
    free(new_conn);
    return NULL;
  }
  new_conn->type = TYPE_CONN;
  new_conn->fd = sock;
  new_conn->size = 0;
  new_conn->eof = 0;
  return new_conn;
}

// TODO: must check read or write (other) event is cached
void delete_conn(struct conn_t *conn) {
  close(conn->fd);
  free(conn->buf);
  free(conn);
}

int read_conn(struct conn_t *conn) {
  ssize_t nn = 0;
  while(conn->size < BUFSIZE) {
    ssize_t n;
    n = read(conn->fd, conn->buf + conn->size, BUFSIZE - conn->size);
    if (n == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      } else if (errno == EINTR) {
        continue;
      } else {
        return -1;
      }
    } else if (n == 0) {
      conn->eof = 1;
      break;
    }
    nn += n;
    conn->size += n;
  }
  return nn;
}

int write_conn(struct conn_t *conn) {
  ssize_t offset = 0, n;
  while(conn->size > 0) {
    n = write(conn->fd, conn->buf + offset, conn->size);
    if (n == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      } else if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    conn->size -= n;
    offset += n;
  }
  if (conn->size > 0) {
    memmove(conn->buf, conn->buf + offset, conn->size);
  }
  return offset;
}

/*
 * Handlers
 */

void handle_read(int kq, struct conn_t *conn) {
  while (1) {
    if (read_conn(conn) == -1) {
      perror("read");
      delete_conn(conn);
      return;
    }
    if (conn->size == 0) {
      if (conn->eof) {
        // fprintf(stderr, "finish conn : %d\n", conn->fd);
        delete_conn(conn);
        return;
      }
      // wait for next read event
      return;
    }

    if (write_conn(conn) == -1) {
      perror("write");
      delete_conn(conn);
      return;
    } else if (conn->size > 0) {
      struct kevent ev;

      // set write event
      EV_SET(&ev, conn->fd, EVFILT_WRITE, EV_ADD|EV_CLEAR, 0, 0, conn);
      if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
        perror("kevent-register");
        delete_conn(conn);
        return;
      }

      if (conn->size == BUFSIZE) {
        // remove edge triggered read event
        EV_SET(&ev, conn->fd, EVFILT_READ, EV_DELETE, 0, 0, conn);
        if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
          perror("kevent-register");
          delete_conn(conn);
          return;
        }
      }
    }
  }
}

void handle_write(int kq, struct conn_t *conn) {
  assert(conn->size > 0);

  int prev = conn->size;
  int n = write_conn(conn);
  if (n == -1) {
    perror("write");
    delete_conn(conn);
    return;
  }
  if (conn->eof && conn->size == 0) {
    // have written all read data
    // fprintf(stderr, "finish conn : %d\n", conn->fd);
    delete_conn(conn);
    return;
  }

  struct kevent ev;
  if (prev == BUFSIZE && n > 0 && !conn->eof) {
    // resume read
    EV_SET(&ev, conn->fd, EVFILT_READ, EV_ADD|EV_CLEAR, 0, 0, conn);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
      perror("kevent-register");
      delete_conn(conn);
      return;
    }
  }
  if (n == prev) {
    // remove write trigger
    EV_SET(&ev, conn->fd, EVFILT_WRITE, EV_DELETE, 0, 0, conn);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
      perror("kevent-register");
      delete_conn(conn);
      return;
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
  laddr.sin_port = htons(3005);
  if ((res = inet_pton(AF_INET, laddrstr, &laddr.sin_addr)) <= 0) {
    if (res == 0) {
      fprintf(stderr, "invalid format for ipv4\n");
    } else {
      perror("inet_pton");
    }
    return 1;
  }

  struct conn_t listener;
  listener.type = TYPE_LISTENER;
  if ((listener.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    return 1;
  }

  fcntl(listener.fd, F_SETFL, O_NONBLOCK);

  fprintf(stderr, "sock : %d\n", listener.fd);

  if (bind(listener.fd, (struct sockaddr *)&laddr, sizeof(laddr)) != 0) {
    perror("bind");
    return 1;
  } else if (listen(listener.fd, NUM_BACKLOG) != 0) {
    perror("listen");
    return 1;
  }

  int kq = kqueue();
  if (kq == -1) {
    perror("kqueue");
    return 1;
  }

  fprintf(stderr, "kqueue : %d\n", kq);

  struct kevent kevs[1];
  EV_SET(&kevs[0], listener.fd, EVFILT_READ, EV_ADD|EV_CLEAR, 0, 0, &listener);

  res = kevent(kq, &kevs[0], 1, NULL, 0, NULL);
  if (res == -1) {
    perror("kevent");
    return 1;
  }
  fprintf(stderr, "kevent : %d\n", res);

  while (1) {
    res = kevent(kq, NULL, 0, kevs, sizeof(kevs) / sizeof(kevs[0]), NULL);
    if (res == -1) {
      perror("kevent-events");
      break;
    }

    int i;
    for (i = 0; i < res; i++) {
      struct conn_t *conn = (struct conn_t *)kevs[i].udata;
      switch (conn->type) {
        case TYPE_LISTENER:
          // Listener
          while (1) {
            int sock = accept(conn->fd, NULL, NULL);
            if (sock == -1) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
              } else if (errno == EINTR) {
                continue;
              }
              perror("accept");
              goto Finish;
            }

            // fprintf(stderr, "accept sock : %d\n", sock);
            fcntl(sock, F_SETFL, O_NONBLOCK);

            struct conn_t *new_conn = create_conn(sock);
            if (new_conn == NULL) {
#define MALLOC_CONN_ERROR_MSG "failed to allocate memory for connection\n"
              write(sock, MALLOC_CONN_ERROR_MSG, sizeof(MALLOC_CONN_ERROR_MSG));
              fprintf(stderr, MALLOC_CONN_ERROR_MSG);
              close(sock);
              continue;
            }

            // register to kqueue
            EV_SET(&kevs[0], new_conn->fd, EVFILT_READ, EV_ADD|EV_CLEAR, 0, 0, new_conn);
            res = kevent(kq, &kevs[0], 1, NULL, 0, NULL);
            if (res == -1) {
              perror("kevent-register");
              goto Finish;
            }
            handle_read(kq, new_conn);
          }
          break;

        case TYPE_CONN:
          switch (kevs[i].filter) {
            case EVFILT_READ:
              handle_read(kq, conn);
              break;

            case EVFILT_WRITE:
              handle_write(kq, conn);
              break;

            default:
              break;
          }
          break;

        default:
          break;
      }
    }
  }

Finish:
  close(listener.fd);

  return 0;
}
