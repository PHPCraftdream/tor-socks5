/*
 * Фикстура блокирующего процесса для тестов установщика (Linux/macOS).
 * Протокол ASCII: при старте печатает "READY:<marker>" и блокируется на stdin.
 * Команда "version" -> "VERSION:<marker>", "exit" или EOF -> код 0.
 * Только stdio/string, C99; без sleep, сети, файлов и потоков.
 */
#include <stdio.h>
#include <string.h>

#define FIXTURE_VERSION "__FIXTURE_VERSION__"

int main(void)
{
    char line[256];

    printf("READY:" FIXTURE_VERSION "\n");
    fflush(stdout);

    while (fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strcmp(line, "version") == 0) {
            printf("VERSION:" FIXTURE_VERSION "\n");
            fflush(stdout);
        } else if (strcmp(line, "exit") == 0) {
            return 0;
        }
    }
    return 0;
}
