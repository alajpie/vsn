#include <hydrogen.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <readline/readline.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 47478
#define PORTSTR "47478"

void die(char *msg) {
  rl_save_prompt();
  rl_redisplay();
  fprintf(stderr, "vsn: %s\n", msg);
  exit(1);
}

void readall(int fd, void *buf, size_t n) {
  size_t k = 0;
  for (size_t i = 0; i < n; i += k) {
    k = read(fd, buf + i, n - i);
    if (!k)
      die("connection reset by peer");
  }
}

void writeall(int fd, const void *buf, size_t n) {
  size_t k = 0;
  for (size_t i = 0; i < n; i += k) {
    k = write(fd, buf + i, n - i);
    if (!k)
      die("connection reset by peer");
  }
}

struct reader_data {
  int fd;
  hydro_kx_session_keypair session_kp;
};

void *reader(void *ptr) {
  struct reader_data data = *(struct reader_data *)ptr;
  for (;;) {
    uint16_t sendlen;
    readall(data.fd, &sendlen, sizeof sendlen);

    int len = ntohs(sendlen);
    uint8_t cipher[len];
    readall(data.fd, cipher, sizeof cipher);

    char plain[len - hydro_secretbox_HEADERBYTES + 1];
    if (hydro_secretbox_decrypt(plain, cipher, len, 0, " vsnvsn ",
                                data.session_kp.rx))
      die("hydro_secretbox_decrypt() failed");
    plain[len - hydro_secretbox_HEADERBYTES] = 0;

    int saved_point = rl_point;
    char *saved_line = rl_copy_text(0, rl_end);
    rl_save_prompt();
    rl_replace_line("", 0);
    rl_redisplay();

    printf("them: %s\n", plain);

    rl_restore_prompt();
    rl_replace_line(saved_line, 0);
    rl_point = saved_point;
    rl_redisplay();
    rl_free(saved_line);
  }
}

int main(int argc, char *argv[]) {
  bool connector = false;
  bool listener = false;
  char opt;

  while ((opt = getopt(argc, argv, "cl")) != -1) {
    switch (opt) {
    case 'c':
      connector = true;
      break;
    case 'l':
      listener = true;
      break;
    }
  }

  if (connector == listener)
    die("usage: vsn -l [port] or vsn -c host [port]");

  if (hydro_init())
    die("hydro_init() failed");

  hydro_kx_keypair static_kp;
  hydro_kx_keygen(&static_kp);

  const uint8_t psk[hydro_kx_PSKBYTES] = " vsnvsnvsnvsnvsnvsnvsnvsnvsnvsn ";
  hydro_kx_session_keypair session_kp;
  hydro_kx_state state;
  int fd;
  uint8_t packet1[hydro_kx_XX_PACKET1BYTES];
  uint8_t packet2[hydro_kx_XX_PACKET2BYTES];
  uint8_t packet3[hydro_kx_XX_PACKET3BYTES];

  if (listener) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd == -1)
      die("socket() failed");

    int on = 1;
    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on))
      die("setsockopt() failed");

    int port = PORT;
    if (argc > optind) {
      char *portstring = argv[optind];
      int portparse = atoi(portstring);
      if (portparse)
        port = portparse;
    }

    const struct sockaddr_in addr = {.sin_family = AF_INET,
                                     .sin_addr.s_addr = htonl(INADDR_ANY),
                                     .sin_port = htons(port)};

    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr))
      die("bind() failed");

    if (listen(lfd, 0))
      die("listen() failed");

    fd = accept(lfd, NULL, NULL);

    readall(fd, packet1, sizeof packet1);
    if (hydro_kx_xx_2(&state, packet2, packet1, psk, &static_kp))
      die("invalid packet 1");
    writeall(fd, packet2, sizeof packet2);

    readall(fd, packet3, sizeof packet3);
    if (hydro_kx_xx_4(&state, &session_kp, NULL, packet3, psk))
      die("invalid packet 3");
  } else if (connector) {
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
      die("socket() failed");

    if (argc <= optind)
      die("usage: vsn -l [port] or vsn -c host [port]");

    struct addrinfo *result;
    struct addrinfo hints = {.ai_family = AF_INET, .ai_flags = AI_NUMERICSERV};
    int code;
    if (argc > (optind + 1))
      code = getaddrinfo(argv[optind], argv[optind + 1], &hints, &result);
    else
      code = getaddrinfo(argv[optind], PORTSTR, &hints, &result);

    if (code)
      die("getaddrinfo() failed");

    if ((connect(fd, result->ai_addr, result->ai_addrlen)))
      die("connect() failed");

    freeaddrinfo(result);

    hydro_kx_xx_1(&state, packet1, psk);
    writeall(fd, packet1, sizeof packet1);

    readall(fd, packet2, sizeof packet2);
    if (hydro_kx_xx_3(&state, &session_kp, packet3, NULL, packet2, psk,
                      &static_kp))
      die("invalid packet 2");
    writeall(fd, packet3, sizeof packet3);
  }

  pthread_t reader_thread;
  struct reader_data data = {
      .fd = fd,
      .session_kp = session_kp,
  };
  pthread_create(&reader_thread, NULL, reader, &data);

  for (;;) {
    char *plain = readline("me: ");
    if (!plain) {
      rl_save_prompt();
      rl_redisplay();
      exit(0);
    }

    int len = strlen(plain);
    if (len + hydro_secretbox_HEADERBYTES > USHRT_MAX)
      die("message too long");
    uint16_t sendlen = htons(hydro_secretbox_HEADERBYTES + len);
    writeall(fd, &sendlen, sizeof sendlen);

    uint8_t cipher[hydro_secretbox_HEADERBYTES + len];
    hydro_secretbox_encrypt(cipher, plain, len, 0, " vsnvsn ", session_kp.tx);
    rl_free(plain);
    writeall(fd, cipher, sizeof cipher);
  }
}
