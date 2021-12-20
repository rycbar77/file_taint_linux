#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

char *leak;
void vuln() {
  if (leak)
    printf("%s", leak);
}

int main() {
  srand(time(0));
  char *secret = (char *)malloc(20);
  int len = read(0, secret, 20);
  char *a;
  char *res;
  int choice0 = rand() % 50;
  int choice1 = rand() % 50;
  for (int i = 0; i < 50; i++) {
    a = strdup(secret);
    if (i == choice0)
      res = strdup(a);
    if (i == choice1)
      leak = strdup(a);
  }

  write(1, res, len);
  vuln();
  return 0;
}