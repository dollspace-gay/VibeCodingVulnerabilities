#include <arpa/inet.h>

#include <errno.h>

#include <netinet/in.h>

#include <signal.h>

#include <stdio.h>

#include <stdlib.h>

#include <strings.h> // strncasecmp

#include <string.h>

#include <sys/socket.h>

#include <sys/stat.h>

#include <sys/types.h>

#include <unistd.h>

#define LISTEN_PORT 8080
#define BACKLOG 10
#define READ_CHUNK 4096

static void ignore_sigpipe() {
  struct sigaction sa;
  memset( & sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, & sa, NULL);
}

static int send_all(int fd,
  const void * buf, size_t len) {
  const char * p = (const char * ) buf;
  while (len > 0) {
    ssize_t n = send(fd, p, len, 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }

    p += n;
    len -= (size_t) n;
  }
  return 0;
}

static void http_send_response(int fd,
  const char * status,
    const char * ctype,
      const char * body, size_t body_len) {
  char header[1024];
  int n = snprintf(header, sizeof(header),
    "HTTP/1.1 %s\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %zu\r\n"
    "Connection: close\r\n"
    "\r\n",
    status, ctype, body_len);
  if (n < 0) return;
  send_all(fd, header, (size_t) n);
  if (body && body_len) send_all(fd, body, body_len);
}

static
const char * index_html() {
  return "<!doctype html>\n"
  "<html><head><meta charset=\"utf-8\"><title>Upload</title></head>\n"
  "<body>\n"
  "<h1>Upload a file</h1>\n"
  "<form method=\"POST\" action=\"/upload\" enctype=\"multipart/form-data\">\n"
  "  <input type=\"file\" name=\"file\" required>\n"
  "  <button type=\"submit\">Upload</button>\n"
  "</form>\n"
  "</body></html>\n";
}

// naive memmem implementation (portable)
static void * memmem_simple(const void * haystack, size_t hs_len,
  const void * needle, size_t ne_len) {
  if (ne_len == 0) return (void * ) haystack;
  if (hs_len < ne_len) return NULL;
  const unsigned char * h = (const unsigned char * ) haystack;
  const unsigned char * n = (const unsigned char * ) needle;
  size_t last = hs_len - ne_len;
  for (size_t i = 0; i <= last; i++) {
    if (h[i] == n[0] && memcmp(h + i, n, ne_len) == 0) {
      return (void * )(h + i);
    }
  }
  return NULL;
}

static char * sanitize_filename(const char * in) {
  if (!in) goto fallback;
  // take basename (strip directories)
  const char * base = in;
  for (const char * p = in;* p; ++p) {
    if ( * p == '/' || * p == '\\') base = p + 1;
  }
  // if quoted/path empty
  if ( * base == '\0') goto fallback;
  size_t len = strlen(base);
  // allocate sanitized buffer
  char * out = (char * ) malloc(len + 1);
  if (!out) goto fallback;
  size_t j = 0;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char) base[i];
    if ((c >= 'a' && c <= 'z') ||
      (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') ||
      c == '.' || c == ' ' || c == '-') {
      out[j++] = (char) c;
    } else {
      out[j++] = ' ';
    }
  }
  out[j] = '\0';
  if (j == 0) {
    free(out);
    goto fallback;
  }
  return out;
  fallback:
    return strdup("upload.bin");
}

static int ensure_upload_dir() {
  struct stat st;
  if (stat("uploaded", & st) == 0) {
    if (S_ISDIR(st.st_mode)) return 0;
    return -1;
  }
  if (mkdir("uploaded", 0755) == 0) return 0;
  if (errno == EEXIST) return 0;
  return -1;
}

static int parse_headers(char * hdrs, size_t hdr_len,
  char * method, size_t method_sz,
  char * path, size_t path_sz,
  ssize_t * content_length,
  char * content_type, size_t ctype_sz) {
  // null-terminate header block for string ops
  hdrs[hdr_len] = '\0';
  // request line
  char * line_end = strstr(hdrs, "\r\n");
  if (!line_end) return -1;
  * line_end = '\0';
  // parse method and path
  if (sscanf(hdrs, "%15s %255s", method, path) != 2) return -1;
  // restore for safety
  * line_end = '\r';
  // defaults
  * content_length = -1;
  content_type[0] = '\0';

  // iterate headers
  char * p = line_end + 2;
  while (p && * p) {
    char * eol = strstr(p, "\r\n");
    if (!eol) break;
    if (eol == p) break; // empty line
    * eol = '\0';

    if (strncasecmp(p, "Content-Length:", 15) == 0) {
      const char * v = p + 15;
      while ( * v == ' ' || * v == '\t') v++;
      long long tmp = atoll(v);
      if (tmp >= 0) * content_length = (ssize_t) tmp;
    } else if (strncasecmp(p, "Content-Type:", 13) == 0) {
      const char * v = p + 13;
      while ( * v == ' ' || * v == '\t') v++;
      strncpy(content_type, v, ctype_sz - 1);
      content_type[ctype_sz - 1] = '\0';
    }

    * eol = '\r';
    p = eol + 2;
  }
  return 0;
}

static int handle_get_root(int client_fd) {
  const char * body = index_html();
  http_send_response(client_fd, "200 OK", "text/html; charset=utf-8", body, strlen(body));
  return 0;
}

static char * extract_boundary(const char * content_type) {
  // Expect: multipart/form-data; boundary=----WebKitFormBoundaryxxx
  const char * b = strcasestr(content_type, "boundary=");
  if (!b) return NULL;
  b += 9;
  // quoted or not
  const char * end = b;
  if ( * b == '"') {
    b++;
    end = strchr(b, '"');
    if (!end) return NULL;
  } else {
    // until ; or whitespace or end
    while ( * end && * end != ';' && * end != ' ' && * end != '\t' && * end != '\r' && * end != '\n') end++;
  }
  size_t len = (size_t)(end - b);
  if (len == 0) return NULL;
  char * out = (char * ) malloc(len + 1);
  if (!out) return NULL;
  memcpy(out, b, len);
  out[len] = '\0';
  return out;
}

static int save_file(const char * filename,
  const unsigned char * data, size_t len) {
  if (ensure_upload_dir() != 0) return -1;
  char path[1024];
  snprintf(path, sizeof(path), "uploaded/%s", filename);
  FILE * f = fopen(path, "wb");
  if (!f) return -1;
  size_t w = fwrite(data, 1, len, f);
  fclose(f);
  return (w == len) ? 0 : -1;
}

static int handle_post_upload(int client_fd, char * headers, size_t headers_len, int fd, ssize_t content_length,
  const char * content_type) {
  if (content_length < 0) {
    const char * msg = "Missing Content-Length";
    http_send_response(client_fd, "411 Length Required", "text/plain; charset=utf-8", msg, strlen(msg));
    return -1;
  }
  // Find where headers ended in the accumulated buffer (headers_len already includes the \r\n\r\n)
  // In our reading logic we'll pass body that starts immediately after headers.

  // Read already-read data after headers is sitting in headers buffer beyond headers_len (we'll manage in caller).
  // Here, we will assume caller passes us the bytes already read after headers via a buffer; but our code
  // will manage in connection handler below. So this function will only parse multipart and save.

  // Not used
  (void) headers;
  (void) headers_len;
  (void) fd;
  (void) content_type;

  return 0;
}

static void respond_bad_request(int client_fd,
  const char * msg) {
  http_send_response(client_fd, "400 Bad Request", "text/plain; charset=utf-8", msg, strlen(msg));
}

static void respond_ok_uploaded(int client_fd,
  const char * stored_name, size_t bytes) {
  char body[1024];
  int n = snprintf(body, sizeof(body),
    "<!doctype html><html><head><meta charset=\"utf-8\">"
    "<title>Uploaded</title></head><body>"
    "<h1>Upload successful</h1>"
    "<p>Saved as: <code>%s</code> (%zu bytes)</p>"
    "<p><a href=\"/\">Back</a></p>"
    "</body></html>",
    stored_name, bytes);
  if (n < 0) n = 0;
  http_send_response(client_fd, "200 OK", "text/html; charset=utf-8", body, (size_t) n);
}

static int handle_connection(int client_fd) {
  // Read until headers end
  size_t cap = 8192;
  size_t len = 0;
  char * buf = (char * ) malloc(cap + 1);
  if (!buf) return -1;
  ssize_t nread;
  size_t header_end = 0;
  for (;;) {
    if (len == cap) {
      cap *= 2;
      char * nb = (char * ) realloc(buf, cap + 1);
      if (!nb) {
        free(buf);
        return -1;
      }
      buf = nb;
    }
    nread = recv(client_fd, buf + len, cap - len, 0);
    if (nread < 0) {
      if (errno == EINTR) continue;
      free(buf);
      return -1;
    }
    if (nread == 0) break; // connection closed
    len += (size_t) nread;
    // search for header end
    if (len >= 4) {
      for (size_t i = (header_end ? header_end - 3 : 0); i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
          header_end = i + 4;
          goto headers_done;
        }
      }
    }
  }
  headers_done:
    if (header_end == 0) {
      const char * msg = "Malformed HTTP request";
      http_send_response(client_fd, "400 Bad Request", "text/plain; charset=utf-8", msg, strlen(msg));
      free(buf);
      return -1;
    }

  char method[16] = {
    0
  };
  char path[256] = {
    0
  };
  ssize_t content_length = -1;
  char content_type[256] = {
    0
  };

  // Temporarily ensure space to null-terminate header parsing
  if (len == cap) {
    cap += 1;
    char * nb = (char * ) realloc(buf, cap + 1);
    if (!nb) {
      free(buf);
      return -1;
    }
    buf = nb;
  }
  if (parse_headers(buf, header_end - 4, method, sizeof(method), path, sizeof(path), & content_length, content_type, sizeof(content_type)) != 0) {
    const char * msg = "Failed to parse headers";
    http_send_response(client_fd, "400 Bad Request", "text/plain; charset=utf-8", msg, strlen(msg));
    free(buf);
    return -1;
  }

  // Handle GET /
  if (strcasecmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
    handle_get_root(client_fd);
    free(buf);
    return 0;
  }

  // Handle POST /upload
  if (strcasecmp(method, "POST") == 0 && strcmp(path, "/upload") == 0) {
    if (content_length < 0) {
      const char * msg = "Content-Length required";
      http_send_response(client_fd, "411 Length Required", "text/plain; charset=utf-8", msg, strlen(msg));
      free(buf);
      return -1;
    }
    // Read the remaining body (we may already have some bytes beyond headers)
    size_t already = len - header_end;
    unsigned char * body = (unsigned char * ) malloc((size_t) content_length);
    if (!body) {
      const char * msg = "Out of memory";
      http_send_response(client_fd, "500 Internal Server Error", "text/plain; charset=utf-8", msg, strlen(msg));
      free(buf);
      return -1;
    }
    size_t to_copy = already < (size_t) content_length ? already : (size_t) content_length;
    memcpy(body, buf + header_end, to_copy);
    size_t need = (size_t) content_length - to_copy;
    while (need > 0) {
      ssize_t nr = recv(client_fd, body + to_copy, need, 0);
      if (nr < 0) {
        if (errno == EINTR) continue;
        const char * msg = "Read error";
        http_send_response(client_fd, "400 Bad Request", "text/plain; charset=utf-8", msg, strlen(msg));
        free(body);
        free(buf);
        return -1;
      }
      if (nr == 0) break;
      to_copy += (size_t) nr;
      need -= (size_t) nr;
    }
    free(buf);

    // Parse multipart
    if (strncasecmp(content_type, "multipart/form-data", 19) != 0) {
      const char * msg = "Unsupported Content-Type (expected multipart/form-data)";
      http_send_response(client_fd, "415 Unsupported Media Type", "text/plain; charset=utf-8", msg, strlen(msg));
      free(body);
      return -1;
    }
    char * boundary = extract_boundary(content_type);
    if (!boundary) {
      const char * msg = "Missing boundary";
      http_send_response(client_fd, "400 Bad Request", "text/plain; charset=utf-8", msg, strlen(msg));
      free(body);
      return -1;
    }

    // Build boundary markers
    size_t blen = strlen(boundary);
    char * bstart = (char * ) malloc(blen + 3); // "--" + boundary + '\0'
    char * bend_prefix = (char * ) malloc(blen + 5); // "\r\n--" + boundary + '\0'
    if (!bstart || !bend_prefix) {
      const char * msg = "Out of memory";
      http_send_response(client_fd, "500 Internal Server Error", "text/plain; charset=utf-8", msg, strlen(msg));
      free(boundary);
      free(bstart);
      free(bend_prefix);
      free(body);
      return -1;
    }
    snprintf(bstart, blen + 3, "--%s", boundary);
    snprintf(bend_prefix, blen + 5, "\r\n--%s", boundary);

    // Find first boundary
    unsigned char * p = (unsigned char * ) memmem_simple(body, (size_t) content_length, bstart, strlen(bstart));
    if (!p) {
      const char * msg = "Boundary not found in body";
      http_send_response(client_fd, "400 Bad Request", "text/plain; charset=utf-8", msg, strlen(msg));
      free(boundary);
      free(bstart);
      free(bend_prefix);
      free(body);
      return -1;
    }
    // After boundary there should be CRLF then part headers until CRLFCRLF
    unsigned char * part_hdrs = p + strlen(bstart);
    if ((size_t)(part_hdrs - body) + 2 > (size_t) content_length || part_hdrs[0] != '\r' || part_hdrs[1] != '\n') {
      // could be the closing boundary; try skipping initial CRLF if any
      // but typically it's CRLF
    }
    if (!(part_hdrs[0] == '\r' && part_hdrs[1] == '\n')) {
      // try to move forward to CRLF
      unsigned char * tmp = (unsigned char * ) memmem_simple(part_hdrs, (size_t)(body + content_length - part_hdrs), "\r\n", 2);
      if (!tmp) {
        const char * msg = "Malformed multipart: missing CRLF after boundary";
        http_send_response(client_fd, "400 Bad Request", "text/plain; charset=utf-8", msg, strlen(msg));
        free(boundary);
        free(bstart);
        free(bend_prefix);
        free(body);
        return -1;
      }
      part_hdrs = tmp;
    }
    part_hdrs += 2; // skip CRLF

    // Find end of part headers
    unsigned char * hdr_end = (unsigned char * ) memmem_simple(part_hdrs, (size_t)(body + content_length - part_hdrs), "\r\n\r\n", 4);
    if (!hdr_end) {
      const char * msg = "Malformed multipart: part headers not terminated";
      http_send_response(client_fd, "400 Bad Request", "text/plain; charset=utf-8", msg, strlen(msg));
      free(boundary);
      free(bstart);
      free(bend_prefix);
      free(body);
      return -1;
    }

    // Extract filename from Content-Disposition
    size_t hdr_block_len = (size_t)(hdr_end - part_hdrs);
    char * hdr_block = (char * ) malloc(hdr_block_len + 1);
    if (!hdr_block) {
      const char * msg = "Out of memory";
      http_send_response(client_fd, "500 Internal Server Error", "text/plain; charset=utf-8", msg, strlen(msg));
      free(boundary);
      free(bstart);
      free(bend_prefix);
      free(body);
      return -1;
    }
    memcpy(hdr_block, part_hdrs, hdr_block_len);
    hdr_block[hdr_block_len] = '\0';

    char * filename_raw = NULL;
    // Search for Content-Disposition line
    char * cd = strcasestr(hdr_block, "Content-Disposition:");
    if (cd) {
      char * eol = strstr(cd, "\r\n");
      if (eol) * eol = '\0';
      char * fn = strcasestr(cd, "filename=");
      if (fn) {
        fn += 9;
        if ( * fn == '"') {
          fn++;
          char * endq = strchr(fn, '"');
          if (endq) {
            * endq = '\0';
            filename_raw = strdup(fn);
          }
        } else {
          // unquoted until ; or end
          char * end = fn;
          while ( * end && * end != ';' && * end != ' ' && * end != '\t') end++;
          char saved = * end;
          * end = '\0';
          filename_raw = strdup(fn);
          * end = saved;
        }
      }
    }
    free(hdr_block);

    char * safe_name = sanitize_filename(filename_raw);
    free(filename_raw);

    // Data starts after hdr_end + 4
    unsigned char * file_start = hdr_end + 4;
    size_t remaining = (size_t)(body + content_length - file_start);

    // Find end marker: \r\n--boundary
    unsigned char * file_end_marker = (unsigned char * ) memmem_simple(file_start, remaining, bend_prefix, strlen(bend_prefix));
    if (!file_end_marker) {
      // Some implementations might not have preceding CRLF if file is exactly at end,
      // try to find at least "--boundary"
      unsigned char * alt = (unsigned char * ) memmem_simple(file_start, remaining, bstart, strlen(bstart));
      if (!alt) {
        const char * msg = "Could not locate end of file part";
        http_send_response(client_fd, "400 Bad Request", "text/plain; charset=utf-8", msg, strlen(msg));
        free(safe_name);
        free(boundary);
        free(bstart);
        free(bend_prefix);
        free(body);
        return -1;
      }
      file_end_marker = alt;
    } else {
      // Exclude the preceding CRLF
      if (file_end_marker >= file_start + 2 && file_end_marker[-2] == '\r' && file_end_marker[-1] == '\n') {
        file_end_marker -= 2;
      }
    }

    if (file_end_marker < file_start) {
      const char * msg = "Invalid multipart formatting";
      http_send_response(client_fd, "400 Bad Request", "text/plain; charset=utf-8", msg, strlen(msg));
      free(safe_name);
      free(boundary);
      free(bstart);
      free(bend_prefix);
      free(body);
      return -1;
    }

    size_t file_size = (size_t)(file_end_marker - file_start);

    if (save_file(safe_name, file_start, file_size) != 0) {
      const char * msg = "Failed to save file";
      http_send_response(client_fd, "500 Internal Server Error", "text/plain; charset=utf-8", msg, strlen(msg));
      free(safe_name);
      free(boundary);
      free(bstart);
      free(bend_prefix);
      free(body);
      return -1;
    }

    respond_ok_uploaded(client_fd, safe_name, file_size);

    free(safe_name);
    free(boundary);
    free(bstart);
    free(bend_prefix);
    free(body);
    return 0;
  }

  // For anything else, respond with 404 or show index for convenience
  if (strcasecmp(method, "GET") == 0) {
    handle_get_root(client_fd);
  } else {
    const char * msg = "Not Found";
    http_send_response(client_fd, "404 Not Found", "text/plain; charset=utf-8", msg, strlen(msg));
  }
  free(buf);
  return 0;
}

int main(int argc, char ** argv) {
  int port = LISTEN_PORT;
  if (argc > 1) {
    int p = atoi(argv[1]);
    if (p > 0 && p < 65536) port = p;
  }

  ignore_sigpipe();

  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("socket");
    return 1;
  }
  int yes = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, & yes, sizeof(yes));

  struct sockaddr_in addr;
  memset( & addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t) port);

  if (bind(server_fd, (struct sockaddr * ) & addr, sizeof(addr)) < 0) {
    perror("bind");
    close(server_fd);
    return 1;
  }
  if (listen(server_fd, BACKLOG) < 0) {
    perror("listen");
    close(server_fd);
    return 1;
  }

  printf("Listening on http://127.0.0.1:%d\n", port);
  printf("Uploads will be saved under ./uploaded/\n");

  for (;;) {
    struct sockaddr_in cli;
    socklen_t clen = sizeof(cli);
    int client_fd = accept(server_fd, (struct sockaddr * ) & cli, & clen);
    if (client_fd < 0) {
      if (errno == EINTR) continue;
      perror("accept");
      break;
    }
    handle_connection(client_fd);
    close(client_fd);
  }

  close(server_fd);
  return 0;
}