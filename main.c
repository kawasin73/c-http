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

// kqueue
#include <sys/event.h>

#define NUM_BACKLOG 4096
#define BUFSIZE 4096

#define TYPE_LISTENER 0
#define TYPE_CONN 1

// returns
#define RES_ERR -1
#define RES_AGAIN -2
#define RES_CLOSED -3

/*
 * Sock
 */

struct sock_t {
  int type;
  int fd;
};

ssize_t sock_read(struct sock_t *sock, void *buf, size_t len) {
  ssize_t n;

eintr:
  n = read(sock->fd, buf, len);

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

ssize_t sock_write(struct sock_t *sock, void *buf, size_t len) {
  ssize_t n;

eintr:
  n = write(sock->fd, buf, len);

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
  struct sock_t sock;
  char *buf;
  int size;
  int state;
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
  new_conn->sock.type = TYPE_CONN;
  new_conn->sock.fd = sock;
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
  struct kevent ev;
  ssize_t res;

  while (conn->state & (CONN_READABLE | CONN_WRITABLE)) {
    // read
    if ((conn->state & CONN_READABLE) && conn->size < BUFSIZE) {
      res = sock_read(&(conn->sock), conn->buf + conn->size,
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
      res = sock_write(&(conn->sock), conn->buf, conn->size);
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

  struct sock_t listener;
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
  EV_SET(&kevs[0], listener.fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0,
         &listener);

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
      struct sock_t *sock = (struct sock_t *)kevs[i].udata;
      switch (sock->type) {
        case TYPE_LISTENER: {
          // Listener
          while (1) {
            int fd = accept(sock->fd, NULL, NULL);
            if (fd == -1) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
              } else if (errno == EINTR) {
                continue;
              }
              perror("accept");
              goto Finish;
            }

            fprintf(stderr, "accept sock : %d\n", fd);
            fcntl(fd, F_SETFL, O_NONBLOCK);

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
                // resume read
                EV_SET(&kevs[0], conn->sock.fd, EVFILT_READ, EV_ADD | EV_CLEAR,
                       0, 0, conn);
                if (kevent(kq, &kevs[0], 1, NULL, 0, NULL) == -1) {
                  perror("kevent-register");
                  delete_conn(conn);
                }
              }
              if (changed & CONN_WRITABLE) {
                // resume write
                EV_SET(&kevs[0], conn->sock.fd, EVFILT_WRITE, EV_ADD | EV_CLEAR,
                       0, 0, conn);
                if (kevent(kq, &kevs[0], 1, NULL, 0, NULL) == -1) {
                  perror("kevent-register");
                  delete_conn(conn);
                }
              }
            }
          }
          break;
        }

        case TYPE_CONN: {
          struct conn_t *conn = (struct conn_t *)sock;
          switch (kevs[i].filter) {
            case EVFILT_READ:
              conn->state |= CONN_READABLE;
              int changed = handler(conn);
              if (changed < 0) {
                delete_conn(conn);
              } else {
                if (changed & CONN_WRITABLE) {
                  // resume write
                  EV_SET(&kevs[0], conn->sock.fd, EVFILT_WRITE,
                         EV_ADD | EV_CLEAR, 0, 0, conn);
                  if (kevent(kq, &kevs[0], 1, NULL, 0, NULL) == -1) {
                    perror("kevent-register");
                    delete_conn(conn);
                  }
                }
                if (conn->state & CONN_READABLE) {
                  // remove edge triggered read event
                  EV_SET(&kevs[0], conn->sock.fd, EVFILT_READ, EV_DELETE, 0, 0,
                         conn);
                  if (kevent(kq, &kevs[0], 1, NULL, 0, NULL) == -1) {
                    perror("kevent-register");
                    delete_conn(conn);
                  }
                }
              }
              break;

            case EVFILT_WRITE: {
              conn->state |= CONN_WRITABLE;
              int changed = handler(conn);
              if (changed < 0) {
                delete_conn(conn);
              } else {
                if (changed & CONN_READABLE) {
                  // resume read
                  EV_SET(&kevs[0], conn->sock.fd, EVFILT_READ,
                         EV_ADD | EV_CLEAR, 0, 0, conn);
                  if (kevent(kq, &kevs[0], 1, NULL, 0, NULL) == -1) {
                    perror("kevent-register");
                    delete_conn(conn);
                  }
                }
                if (conn->state & CONN_WRITABLE) {
                  // remove edge triggered write event
                  EV_SET(&kevs[0], conn->sock.fd, EVFILT_WRITE, EV_DELETE, 0, 0,
                         conn);
                  if (kevent(kq, &kevs[0], 1, NULL, 0, NULL) == -1) {
                    perror("kevent-register");
                    delete_conn(conn);
                  }
                }
              }
              break;
            }

            default:
              break;
          }
          break;
        }

        default:
          break;
      }
    }
  }

Finish:
  close(listener.fd);

  return 0;
}
