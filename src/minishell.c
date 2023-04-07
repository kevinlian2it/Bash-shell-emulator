#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <pwd.h>

#define BRIGHTBLUE "\x1b[34;1m"
#define DEFAULT    "\x1b[0m"

#define MAX_INPUT_SIZE 1024
#define MAX_PATH_SIZE 1024

void run_shell();

void sigint_handler(int sig) {
    printf("\n");
    run_shell();
}

char *expand_tilde(const char *path) {
    if (path[0] == '~') {
        char *new_path = malloc(MAX_PATH_SIZE);
        uid_t uid = getuid();
        struct passwd *pw = getpwuid(uid);

        if (pw) {
            strcpy(new_path, pw->pw_dir);
            strcat(new_path, path + 1);
            return new_path;
        }
    }
    return strdup(path);
}

void change_directory(char *path) {
    char *expanded_path = expand_tilde(path);

    if (chdir(expanded_path) != 0) {
        perror("chdir");
    }

    free(expanded_path);
}
char *get_next_token(char *input, int *pos) {
    int start = *pos;
    char *token;
    int token_len = 0;

    while (input[*pos] != '\0') {
        if (input[*pos] == '\"') {
            (*pos)++;
            while (input[*pos] != '\0') {
                if (input[*pos] == '\"') {
                    (*pos)++;
                    break;
                }
                token_len++;
                (*pos)++;
            }
        } else {
            while (input[*pos] != ' ' && input[*pos] != '\0') {
                (*pos)++;
                token_len++;
            }
        }

        if (input[*pos] == ' ') {
            (*pos)++;
            break;
        }
    }

    if (token_len > 0) {
        token = malloc(token_len + 1);
        int token_pos = 0;
        for (int i = start; i < *pos; i++) {
            if (input[i] != '\"') {
                token[token_pos++] = input[i];
            }
        }
        token[token_len] = '\0';
    } else {
        token = NULL;
    }

    return token;
} 
/*
char *get_next_token(char *input, int *pos) {
    int start = *pos;
    char *token;
    int token_len = 0;
    int in_quotes = 0;

    while (input[*pos] != '\0') {
        if (input[*pos] == '\"') {
            in_quotes = !in_quotes;
            (*pos)++;
        } else {
            if (input[*pos] == ' ' && !in_quotes) {
                break;
            }
            token_len++;
            (*pos)++;
        }
    }

    if (token_len > 0) {
        token = malloc(token_len + 1);
        int token_pos = 0;
        for (int i = start; i < start + token_len + (in_quotes ? 1 : 0); i++) {
            if (input[i] != '\"') {
                token[token_pos++] = input[i];
            }
        }
        token[token_len] = '\0';
    } else {
        token = NULL;
    }

    if (input[*pos] == ' ') {
        (*pos)++;
    }
    printf("Token: '%s'\n", token);
    return token;
}
*/
void run_shell() {
    char input[MAX_INPUT_SIZE];
    char cwd[MAX_PATH_SIZE];

    while (1) {
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            printf("%s[%s]%s$ ", BRIGHTBLUE, cwd, DEFAULT);
        } else {
            perror("getcwd");
            exit(EXIT_FAILURE);
        }

        if (fgets(input, MAX_INPUT_SIZE, stdin) == NULL) {
            printf("\n");
            exit(EXIT_SUCCESS);
        }

        input[strcspn(input, "\n")] = 0;

        int pos = 0;
        char *command = get_next_token(input, &pos);
	printf("Input command: '%s'\n", command);
        if (command == NULL) {
            continue;
        } else if (strcmp(command, "exit") == 0) {
            free(command);
            exit(EXIT_SUCCESS);
        } else if (strcmp(command, "cd") == 0) {
            char *path = get_next_token(input, &pos);
            printf("Path is: '%s'\n", path);
            if (path == NULL) {
                change_directory("~");
            } else {
                change_directory(path);
                free(path);
            }
        } else {
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork");
                exit(EXIT_FAILURE);
            } else if (pid == 0) {
                char *args[MAX_INPUT_SIZE] = {command};
                int i = 1;
                char *arg;
                while ((arg = get_next_token(input, &pos)) != NULL) {
                    args[i++] = arg;
                }
  	        args[i] = NULL;	
                if (execvp(command, args) == -1) {
                    perror("execvp");
                    exit(EXIT_FAILURE);
                }
            } else {
                int status;
                waitpid(pid, &status, 0);
            }
        }

        free(command);
    }
}

int main() {
    signal(SIGINT, sigint_handler);
    run_shell();
    return 0;
}
