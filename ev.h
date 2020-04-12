struct ev_loop_t;
struct ev_sock_t;

typedef void ev_handler(struct ev_loop_t *loop, struct ev_sock_t *sock,
                        void *data);

struct ev_loop_t {
  int mainfd;
};

struct ev_sock_t {
  int fd;
  void *data;
  ev_handler *read_cb;
  ev_handler *write_cb;
};

struct ev_loop_t *ev_create_loop();
int ev_run_loop(struct ev_loop_t *loop);
int ev_init_sock(struct ev_sock_t *sock, int fd, void *data);
int ev_register_read(struct ev_loop_t *loop, struct ev_sock_t *sock,
                     ev_handler *cb);
int ev_unregister_read(struct ev_loop_t *loop, struct ev_sock_t *sock);
int ev_register_write(struct ev_loop_t *loop, struct ev_sock_t *sock,
                      ev_handler *cb);
int ev_unregister_write(struct ev_loop_t *loop, struct ev_sock_t *sock);
