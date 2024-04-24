#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_COMMAND_LEN 512
#define MAX_RESPONSE_LEN 1024

char* get_overlay2_location(const char* container_name) {
    char command[MAX_COMMAND_LEN];
    char response[MAX_RESPONSE_LEN];

    // Execute docker container inspect command
    snprintf(command, MAX_COMMAND_LEN, "docker container inspect %s | jq -r '.[0].GraphDriver.Data.MergedDir'", container_name);
    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to execute command");
        exit(EXIT_FAILURE);
    }

    // Read the response from the command
    if (fgets(response, MAX_RESPONSE_LEN, fp) == NULL) {
        perror("Failed to read command output");
        exit(EXIT_FAILURE);
    }

    pclose(fp);

    // Remove trailing newline character
    response[strcspn(response, "\n")] = '\0';

    // Allocate memory for the overlay2 location
    char* overlay2_location = strdup(response);
    if (overlay2_location == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    return overlay2_location;
}

int main() {
    char container_name[128];

    printf("Enter the container name: ");
    fgets(container_name, sizeof(container_name), stdin);
    container_name[strcspn(container_name, "\n")] = '\0'; // Remove trailing newline if present

    char* overlay2_location = get_overlay2_location(container_name);
    printf("Overlay2 location for container '%s': %s\n", container_name, overlay2_location);

    free(overlay2_location);

    return 0;
}