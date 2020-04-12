#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

// kqueue
#include <sys/event.h>

#include "const.h"
#include "ev.h"

struct ev_loop_t *ev_create_loop() {
  int kq = kqueue();
  if (kq == -1) {
    perror("kqueue");
    return NULL;
  }
  struct ev_loop_t *loop = (struct ev_loop_t *)malloc(sizeof(struct ev_loop_t));
  loop->mainfd = kq;
  return loop;
}

int ev_run_loop(struct ev_loop_t *loop) {
  int res;
  struct kevent kevs[2];
  res =
      kevent(loop->mainfd, NULL, 0, kevs, sizeof(kevs) / sizeof(kevs[0]), NULL);
  if (res == -1) {
    perror("kevent-events");
    return RES_ERR;
  }

  int i;
  for (i = 0; i < res; i++) {
    struct ev_sock_t *sock = (struct ev_sock_t *)kevs[i].udata;
    switch (kevs[i].filter) {
      case EVFILT_READ:
        assert(sock->read_cb != NULL);
        sock->read_cb(loop, sock, sock->data);
        break;

      case EVFILT_WRITE:
        assert(sock->write_cb != NULL);
        sock->write_cb(loop, sock, sock->data);
        break;

      default:
        assert("not expected kqueue filter" || 0);
        break;
    }
  }

  return RES_OK;
}

int ev_init_sock(struct ev_sock_t *sock, int fd, void *data) {
  int res = fcntl(fd, F_SETFL, O_NONBLOCK);
  if (res == -1) {
    // TODO: handle fnctl error
    return RES_ERR;
  }
  sock->fd = fd;
  sock->data = data;
  sock->read_cb = NULL;
  sock->write_cb = NULL;
  return RES_OK;
}

int ev_register_read(struct ev_loop_t *loop, struct ev_sock_t *sock,
                     ev_handler *cb) {
  if (sock->read_cb != NULL) {
    fprintf(stderr, "sock : %d : read_cb is already set.\n", sock->fd);
    return RES_ERR;
  }
  sock->read_cb = cb;

  struct kevent kevs[1];
  EV_SET(&kevs[0], sock->fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, sock);
  if (kevent(loop->mainfd, &kevs[0], 1, NULL, 0, NULL) == -1) {
    // TODO: handle kevent error
    return RES_ERR;
  }
  return RES_OK;
}

int ev_unregister_read(struct ev_loop_t *loop, struct ev_sock_t *sock) {
  if (sock->read_cb == NULL) {
    fprintf(stderr, "sock : %d : read_cb is not set.\n", sock->fd);
    return RES_ERR;
  }
  sock->read_cb = NULL;

  struct kevent kevs[1];
  EV_SET(&kevs[0], sock->fd, EVFILT_READ, EV_DELETE, 0, 0, sock);
  if (kevent(loop->mainfd, &kevs[0], 1, NULL, 0, NULL) == -1) {
    // TODO: handle kevent error
    return RES_ERR;
  }
  return RES_OK;
}

int ev_register_write(struct ev_loop_t *loop, struct ev_sock_t *sock,
                      ev_handler *cb) {
  if (sock->write_cb != NULL) {
    fprintf(stderr, "sock : %d : write_cb is already set.\n", sock->fd);
    return RES_ERR;
  }
  sock->write_cb = cb;

  struct kevent kevs[1];
  EV_SET(&kevs[0], sock->fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, sock);
  if (kevent(loop->mainfd, &kevs[0], 1, NULL, 0, NULL) == -1) {
    // TODO: handle kevent error
    return RES_ERR;
  }
  return RES_OK;
}

int ev_unregister_write(struct ev_loop_t *loop, struct ev_sock_t *sock) {
  if (sock->write_cb == NULL) {
    fprintf(stderr, "sock : %d : write_cb is not set.\n", sock->fd);
    return RES_ERR;
  }
  sock->write_cb = NULL;

  struct kevent kevs[1];
  EV_SET(&kevs[0], sock->fd, EVFILT_WRITE, EV_DELETE, 0, 0, sock);
  if (kevent(loop->mainfd, &kevs[0], 1, NULL, 0, NULL) == -1) {
    // TODO: handle kevent error
    return RES_ERR;
  }
  return RES_OK;
}
